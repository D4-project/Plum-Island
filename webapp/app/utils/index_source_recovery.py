"""Recover unavailable sources without discarding indexed capture history."""

import ipaddress
import json
import logging
import time

from meilisearch.errors import MeilisearchApiError

from app.utils.index_generations import CONTROL, GenerationClient, read_json
from app.utils.index_reconciliation import (
    FIELDS,
    index_for,
    ingest_sources,
    journal_id,
    load_document,
    remove_document,
    write_barrier,
)
from app.utils.index_sources import ExcludedSource
from app.utils.kvrocks import KVrocksIndexer
from app.utils.result_parser import is_external_ip

logger = logging.getLogger(__name__)
MISSING_SOURCES = CONTROL + "missing_sources"
MISSING_SOURCE_RETRY_SECONDS = 300
MISSING_SOURCE_GRACE_SECONDS = 86400
MISSING_SOURCE_BATCH_SIZE = 16

SOURCE_CONFLICT = (
    "Non-public source conflicts with indexed history or incremental "
    "work. Review source/index consistency before retrying."
)


def document_not_found(error):
    """Recognize a missing document independently of missing-index errors."""
    return error.status_code == 404 and error.code == "document_not_found"


def defer_missing_source(raw, job, uid):
    """Keep a known capture searchable while its raw document is unavailable."""
    processed = CONTROL + "processed:" + job["id"]
    with write_barrier(background=True):
        if raw.sismember(CONTROL + "deleted:" + journal_id(job), uid):
            raw.sadd(processed, uid)
            return True
        base = GenerationClient(raw, job["parent"])
        if not base.sismember("all_uids", uid):
            return False
        target = GenerationClient(raw, job["id"], writable=True)
        if job["full"]:
            document = load_document(base, uid, preserve_storage=True)
            index_for(target).add_documents_batch([document])
            coverage = base.get(f"coverage:{uid}")
            contributions = document["_contributions"]
            pipe = target.pipeline()
            if coverage:
                pipe.set(f"coverage:{uid}", coverage)
            if contributions:
                pipe.set(
                    f"contributions:{uid}", json.dumps(contributions, sort_keys=True)
                )
                for rule_id in contributions:
                    pipe.sadd(f"rule_matches:{rule_id}", uid)
            pipe.execute()
        elif target.sismember("rule_drift", uid):
            # A missing raw document is retried independently of rule drift.
            target.srem("rule_drift", uid)
        pipe = raw.pipeline(transaction=True)
        pipe.zadd(
            MISSING_SOURCES, {uid: time.time() + MISSING_SOURCE_RETRY_SECONDS}, nx=True
        )
        pipe.sadd(processed, uid)
        queued, _ = pipe.execute()
        if queued:
            logger.info("Deferred missing Meilisearch capture %s", uid)
    return True


def retry_missing_sources(raw, sources, exports_pending, ready):
    """Recheck a bounded set of missing captures once the main retag is done."""
    if read_json(raw, "job", {}).get("phase") != "done":
        return
    snapshot = read_json(raw, "published", {})
    if not snapshot:
        return
    uids = raw.zrangebyscore(
        MISSING_SOURCES, "-inf", time.time(), start=0, num=MISSING_SOURCE_BATCH_SIZE
    )
    sources.use_candidates(uids)
    active = GenerationClient(raw, writable=True)
    for uid in uids:
        if not ready():
            return
        if not active.sismember("all_uids", uid):
            raw.zrem(MISSING_SOURCES, uid)
            continue
        # On any backend failure the UID remains queued for a later worker.
        raw.zadd(MISSING_SOURCES, {uid: time.time() + MISSING_SOURCE_RETRY_SECONDS})
        try:
            source = sources.get_document(uid)
        except MeilisearchApiError as error:
            if not document_not_found(error):
                raise
            _remove_missing_if_expired(raw, active, sources, exports_pending, uid)
        except ExcludedSource:
            logger.warning("Deferred capture %s now has a non-public source", uid)
        else:
            source = source if isinstance(source, dict) else vars(source)
            ingest_sources(raw, [source], snapshot)
            raw.zrem(MISSING_SOURCES, uid)


def _remove_missing_if_expired(raw, active, sources, exports_pending, uid):
    """Remove verified old orphans only with a healthy, idle export path."""
    cutoff = time.time() - MISSING_SOURCE_GRACE_SECONDS
    observed = KVrocksIndexer.normalize_timestamp(
        active.hget(f"doc:{uid}", "last_seen")
    )
    if observed is None or observed >= cutoff or exports_pending is None:
        return
    stats = sources.index.get_stats()
    if not stats.number_of_documents or stats.is_indexing:
        return
    if sources.index.get_tasks(
        {"statuses": ["enqueued", "processing"], "limit": 1}
    ).results:
        return
    if exports_pending():
        return
    try:
        sources.index.get_document(uid)
    except MeilisearchApiError as error:
        if not document_not_found(error):
            raise
    else:
        # The report arrived while checking the export queues.
        return
    with write_barrier(background=True):
        before = load_document(active, uid)
        last_seen = KVrocksIndexer.normalize_timestamp(before.get("last_seen"))
        if last_seen != observed:
            return
        remove_document(active, uid, before)
        raw.zrem(MISSING_SOURCES, uid)
        logger.warning("Removed expired capture %s missing from Meilisearch", uid)


def _has_references(client, uid, addresses):
    """Treat partial indexes, contribution records and coverage as live data."""
    pipe = client.pipeline(transaction=False)
    pipe.zscore("first_seen_index", uid)
    pipe.zscore("last_seen_index", uid)
    pipe.sismember("all_uids", uid)
    for name in ("uid", "contributions", "coverage"):
        pipe.exists(f"{name}:{uid}")
    for field in FIELDS:
        pipe.scard(f"{field}s:{uid}")
    for address in addresses:
        pipe.sismember(f"ip:{address}", uid)
    values = pipe.execute()
    return any(value is not None for value in values[:2]) or any(values[2:])


def _matching_archive(metadata, address):
    """Recognize only a detached date hash for the same non-public address."""
    if set(metadata) - {"ip", "first_seen", "last_seen"}:
        return False
    try:
        retained = ipaddress.ip_address(metadata.get("ip"))
        return not is_external_ip(str(retained)) and (
            not address or retained == ipaddress.ip_address(address)
        )
    except ValueError:
        return False


def orphan_exclusion_metadata(raw, job, uid, address=None):
    """Return intact detached metadata, or None when exclusion would lose data.

    Empty metadata is valid for a Meili-only source. A retained hash must contain
    only IP/date fields, match the excluded source address, and have no indexed
    references in either generation. Never merge conflicting staging metadata.
    """
    if not job.get("full"):
        return None
    clients = [GenerationClient(raw, job[key]) for key in ("parent", "id")]
    documents = [client.hgetall(f"doc:{uid}") for client in clients]
    metadata = documents[0] or documents[1]
    if any(document and document != metadata for document in documents):
        return None
    addresses = {address} if address else set()
    if metadata:
        if not _matching_archive(metadata, address):
            return None
        addresses.add(metadata["ip"])
    if any(_has_references(client, uid, addresses) for client in clients):
        return None
    return metadata


def requeue_orphan_exclusion(raw, job):
    """Queue one narrowly validated recovery without replacing frozen inputs.

    Only the earlier orphan-hash conflict is eligible. A durable marker prevents
    an endless restart if source validation subsequently finds another conflict.
    The scheduler launches the normal worker, which rechecks source and snapshot.
    """
    if job.get("phase") != "blocked" or job.get("message") != SOURCE_CONFLICT:
        return job
    with write_barrier():
        current = read_json(raw, "job", {})
        if (
            current.get("id") != job.get("id")
            or current.get("phase") != "blocked"
            or current.get("message") != SOURCE_CONFLICT
        ):
            return current
        marker = CONTROL + "g:" + current["id"] + ":orphan_recovery:v1"
        if raw.exists(marker):
            return current
        pending = current.get("pending_uids", [])
        pipe = raw.pipeline(transaction=False)
        for uid in pending:
            pipe.sismember(CONTROL + "processed:" + current["id"], uid)
        remaining = [uid for uid, done in zip(pending, pipe.execute()) if not done]
        if not remaining or not orphan_exclusion_metadata(raw, current, remaining[0]):
            return current
        resumed = dict(
            current,
            phase="paused",
            retry_at=None,
            message="Retained orphan timestamps; queued source exclusion recheck",
        )
        pipe = raw.pipeline(transaction=True)
        pipe.set(marker, "1")
        pipe.set(CONTROL + "job", json.dumps(resumed, sort_keys=True))
        pipe.execute()
        return resumed
