"""Backfill port evidence in the active tag generation, newest first."""

import json
import time

from meilisearch.errors import MeilisearchApiError

from app.utils.index_generations import (
    ACTIVE,
    CONTROL,
    GenerationClient,
    generation_prefix,
    read_json,
    write_json,
)
from app.utils.index_reconciliation import parsed_source, write_barrier
from app.utils.index_source_recovery import document_not_found
from app.utils.index_sources import ExcludedSource
from app.utils.scan_ports import build_scan_port, read_scan_ports
from app.utils.tag_reconciliation import RulePlan

BACKFILL = "scan_port_backfill_v1"
BACKFILL_DONE = CONTROL + BACKFILL + ":done"
WINDOW_SECONDS = 90 * 86400
BATCH_SIZE = 32
HISTORY = "last_seen_index"


def _next_page(client, state, limit):
    """Seek by score and verify the cursor within that timestamp only."""
    raw = client.raw
    with write_barrier(background=True):
        history = client.resolve_many([HISTORY])[HISTORY]
        upper = state.get("score", state["end"])
        offset = state.get("offset", 0)
        if offset:
            boundary = raw.zrevrangebyscore(
                history, upper, upper, start=offset - 1, num=1
            )
            if boundary != [state["anchor"]]:
                # An observation moved while we were reading Meili. Revisit
                # only this timestamp; summaries already present are skipped.
                offset = 0
        rows = raw.zrevrangebyscore(
            history, upper, state["start"], start=offset, num=limit, withscores=True
        )
    if not rows:
        return rows, 0
    lowest_score = rows[-1][1]
    consumed = sum(score == lowest_score for _, score in rows)
    return rows, consumed + (offset if lowest_score == upper else 0)


def _build_summaries(sources, plan, client, uids):
    covered = read_scan_ports(client, uids)
    uids = [uid for uid in uids if uid not in covered]
    sources.use_candidates(uids)
    summaries = {}
    for uid in uids:
        try:
            source = sources.get_document(uid)
            source = source if isinstance(source, dict) else vars(source)
        except ExcludedSource:
            continue
        except MeilisearchApiError as error:
            if not document_not_found(error):
                raise
            continue
        try:
            document = parsed_source(source, plan.snapshot)
        except ValueError:
            continue
        summary = build_scan_port(source, document, plan)
        if summary is not None:
            summaries[uid] = summary
    return summaries


def _commit_page(client, state, rows, summaries, offset):
    """Publish the independent keys and their checkpoint together."""
    raw = client.raw
    with write_barrier(background=True):
        if (raw.get(ACTIVE) or "") != client.generation:
            return False
        uids = list(summaries)
        previous = read_scan_ports(client, uids)
        check = client.pipeline(transaction=False)
        for uid in uids:
            check.zscore(HISTORY, uid)
            check.sismember("rule_drift", uid)
        expected = dict(rows)
        result = check.execute() if uids else []
        pending = [
            uid
            for uid, seen, drift in zip(uids, result[::2], result[1::2])
            if uid not in previous and seen == expected[uid] and not drift
        ]
        pipe = raw.pipeline(transaction=True)
        generation = client.generation
        keys = [f"scan_port:{uid}" for uid in pending]
        if generation and keys:
            pipe.sadd(GenerationClient.owned(generation), *keys)
        prefix = generation_prefix(generation)
        for uid, key in zip(pending, keys):
            pipe.set(prefix + key, json.dumps(summaries[uid], separators=(",", ":")))
        state.update(
            anchor=rows[-1][0],
            score=rows[-1][1],
            offset=offset,
            checked=state["checked"] + len(rows),
            written=state["written"] + len(pending),
            heartbeat=time.time(),
        )
        pipe.set(CONTROL + BACKFILL, json.dumps(state))
        pipe.execute()
    return True


def backfill_scan_ports(raw, sources, wait, stopping, *, batch_size=BATCH_SIZE):
    """Read one 90-day window frozen at startup with a durable page cursor."""
    if raw.get(BACKFILL_DONE) == "1" or stopping():
        return
    generation = raw.get(ACTIVE) or ""
    snapshot = read_json(raw, "published") or read_json(raw, "desired")
    if not snapshot:
        return
    plan = RulePlan(snapshot)
    client = GenerationClient(raw, generation)
    state = read_json(raw, BACKFILL, {})
    if (
        state.get("generation") != generation
        or state.get("revision") != snapshot["revision"]
    ):
        end = state.get("end", int(time.time()))
        state = {
            "generation": generation,
            "revision": snapshot["revision"],
            "start": end - WINDOW_SECONDS,
            "end": end,
            "checked": 0,
            "written": 0,
            "heartbeat": time.time(),
        }
        write_json(raw, BACKFILL, state)
    while wait(stopping):
        rows, offset = _next_page(client, state, batch_size)
        if not rows:
            raw.set(BACKFILL_DONE, "1")
            return
        summaries = _build_summaries(sources, plan, client, [uid for uid, _ in rows])
        if not wait(stopping) or not _commit_page(
            client, state, rows, summaries, offset
        ):
            return


def scan_port_backfill_status(raw):
    """Expose progress without changing the normal reconciliation checkpoint."""
    if raw.get(BACKFILL_DONE) == "1":
        return {}
    state = read_json(raw, BACKFILL, {})
    if not state:
        return {}
    return {
        "phase": "backfilling_scan_ports",
        "revision": state["revision"][:12],
        "processed": state["checked"],
        "total": state.get("total"),
        "heartbeat": state["heartbeat"],
    }
