"""Durable background reconciliation and the common ingestion write barrier."""

import json
import os
import time
from contextlib import contextmanager, ExitStack
from pathlib import Path
from uuid import uuid4

try:
    from .kvrocks import KVrocksIndexer
    from .search_query import iter_criteria
    from .index_generations import (
        ACTIVE,
        CONTROL,
        GenerationClient,
        file_lock,
        read_json,
        write_json,
    )
    from .tag_reconciliation import RulePlan, code_revision, fingerprint
    from .result_parser import parse_json, prepare_kvrocks_document
except ImportError:
    from kvrocks import KVrocksIndexer
    from search_query import iter_criteria
    from index_generations import (
        ACTIVE,
        CONTROL,
        GenerationClient,
        file_lock,
        read_json,
        write_json,
    )
    from tag_reconciliation import RulePlan, code_revision, fingerprint
    from result_parser import parse_json, prepare_kvrocks_document

FIELDS = (
    "net",
    "fqdn",
    "fqdn_requested",
    "domain_requested",
    "host",
    "domain",
    "tld",
    "tag",
    "port",
    "port_protocol",
    "http_title",
    "http_favicon_path",
    "http_favicon_mmhash",
    "http_favicon_md5",
    "http_favicon_sha256",
    "http_cookiename",
    "http_etag",
    "http_header",
    "http_headval",
    "http_server",
    "x509_issuer",
    "x509_issuer_cn",
    "x509_md5",
    "x509_sha1",
    "x509_sha256",
    "x509_subject",
    "x509_subject_cn",
    "x509_san",
    "banner",
    "service",
    "engine",
)


class SnapshotInvalid(ValueError):
    """Frozen inputs cannot execute; a corrected revision needs a fresh run."""


def state_directory():
    """All writers to one backend must share this controller-local directory."""
    default = Path(__file__).resolve().parents[1] / "index_state"
    return Path(os.environ.get("PLUM_INDEX_STATE_DIR", str(default)))


@contextmanager
def write_barrier(background=False):
    """Give waiting foreground writers priority between background units."""
    directory = state_directory()
    if not background:
        with file_lock(directory / "ingestion.lock", shared=True):
            with file_lock(directory / "writes.lock"):
                yield
        return
    while True:
        with ExitStack() as locks:
            try:
                locks.enter_context(
                    file_lock(directory / "ingestion.lock", blocking=False)
                )
                locks.enter_context(
                    file_lock(directory / "writes.lock", blocking=False)
                )
            except BlockingIOError:
                pass
            else:
                yield
                return
        time.sleep(0.01)


def index_for(client):
    """Use the existing field/index implementation with an explicit keyspace."""
    indexer = KVrocksIndexer.__new__(KVrocksIndexer)
    indexer.r = client
    return indexer


def load_document(client, uid):
    """Reconstruct normalized fields and accumulated timestamps in one batch."""
    pipe = client.pipeline(transaction=False)
    pipe.hgetall(f"doc:{uid}")
    for field in FIELDS:
        pipe.smembers(f"{field}s:{uid}")
    pipe.get(f"contributions:{uid}")
    values = pipe.execute()
    document = dict(values[0], uid=uid, id=uid)
    document.update({field: sorted(items) for field, items in zip(FIELDS, values[1:])})
    if not document["engine"]:
        document["engine"] = ["nmap"]
    document["_contributions"] = json.loads(values[-1]) if values[-1] else {}
    return document


def coverage_profile(snapshot):
    """Share one immutable profile among all captures processed with it."""
    return {"code": snapshot["code"], "parser": snapshot["parser"]}


def parsed_source(source, snapshot):
    """Parse without tags; the contribution engine owns rule dependency order."""
    parsed = parse_json(source, snapshot["parser"], tag_rules=[])
    if parsed is None:
        raise ValueError("Source capture is not indexable under the frozen parser")
    return prepare_kvrocks_document(source, parsed, tag_rules=[])


def merge_history(document, before):
    """Merge source dates with accumulated Kvrocks history, never overwrite it."""
    normalize = KVrocksIndexer.normalize_timestamp
    for field, operation in (("first_seen", min), ("last_seen", max)):
        values = [
            normalize(value) for value in (document.get(field), before.get(field))
        ]
        values = [value for value in values if value is not None]
        if values:
            document[field] = operation(values)


def save_document(
    client, document, contributions, snapshot, *, old=None, full=True
):  # pylint: disable=too-many-arguments
    """Apply idempotently, including memberships lost from a mutable COW parent."""
    uid = document["uid"]
    indexer = index_for(client)
    if old:
        pipe = client.pipeline()
        for field in FIELDS if full else ("tag",):
            for value in old.get(field, []):
                pipe.srem(f"{field}:{value}", uid)
        for rule_id in old.get("_contributions", {}):
            pipe.srem(f"rule_matches:{rule_id}", uid)
        pipe.execute()
    if full:
        indexer.add_documents_batch([document])
    else:
        indexer.replace_field_values_batch("tag", [document])
    previous_contributions = client.get(f"contributions:{uid}")
    previous_contributions = (
        json.loads(previous_contributions) if previous_contributions else {}
    )
    pipe = client.pipeline()
    for rule_id in previous_contributions:
        pipe.srem(f"rule_matches:{rule_id}", uid)
    for rule_id in contributions:
        pipe.sadd(f"rule_matches:{rule_id}", uid)
    if full:
        profile = coverage_profile(snapshot)
        profile_id = fingerprint(profile)
        client.raw.set(
            CONTROL + "coverage:" + profile_id,
            json.dumps(profile, sort_keys=True),
            nx=True,
        )
        pipe.set(f"coverage:{uid}", profile_id)
    pipe.set(f"contributions:{uid}", json.dumps(contributions, sort_keys=True))
    pipe.execute()


def ingest_sources(raw, sources, fallback_snapshot):
    """Journal before changing the active index; export retry remains idempotent."""
    plan = None
    generation = None
    for source in sources:
        while True:
            active = raw.get(ACTIVE) or ""
            if plan is None or generation != active:
                snapshot = read_json(raw, "published", fallback_snapshot)
                plan = RulePlan(snapshot)
                generation = active
            else:
                snapshot = plan.snapshot
            document = parsed_source(source, snapshot)
            tags, contributions = plan.evaluate(document, force=True)
            document["tag"] = tags
            with write_barrier():
                if (raw.get(ACTIVE) or "") != generation:
                    continue
                _ingest_document(
                    raw, source, generation, snapshot, document, contributions
                )
            break


def _ingest_document(raw, source, generation, snapshot, document, contributions):
    """Journal and write one precomputed capture under the barrier."""
    client = GenerationClient(raw, generation, writable=True)
    job = read_json(raw, "job")
    uid = document["uid"]
    old = load_document(client, uid)
    if job and job["phase"] != "done":
        raw.srem(CONTROL + "deleted:" + job["id"], uid)
        raw.rpush(
            CONTROL + "journal:" + job["id"],
            json.dumps(
                {
                    "source": source,
                    "before": old,
                }
            ),
        )
    save_document(client, document, contributions, snapshot)


def ingest_indexer_sources(indexer, sources):
    """Use the managed writer when enabled; leave legacy adapters unchanged."""
    if getattr(indexer, "accepts_source_documents", False) is not True:
        return False
    desired = read_json(indexer.raw, "desired")
    if desired is None:
        return False
    ingest_sources(indexer.raw, sources, desired)
    return True


def remove_document(client, uid, before):  # pylint: disable=too-many-locals
    """Remove both index directions, including inherited memberships on replay."""
    from netaddr import IPNetwork  # pylint: disable=import-outside-toplevel

    current = load_document(client, uid)
    pipe = client.pipeline()
    ips = {item.get("ip") for item in (current, before)} - {None, ""}
    for item in (current, before):
        for field in FIELDS:
            for value in item.get(field, []):
                pipe.srem(f"{field}:{value}", uid)
    for field in FIELDS:
        pipe.delete(f"{field}s:{uid}")
    for ip in ips:
        pipe.srem(f"ip:{ip}", uid)
        for mask in range(16, 25):
            network = str(IPNetwork(f"{ip}/{mask}").network) + f"/{mask}"
            pipe.srem(f"net:{network}", uid)
    contributions = client.get(f"contributions:{uid}")
    rule_ids = set(json.loads(contributions) if contributions else {}) | set(
        before.get("_contributions", {})
    )
    for rule_id in rule_ids:
        pipe.srem(f"rule_matches:{rule_id}", uid)
    pipe.srem("all_uids", uid)
    pipe.zrem("first_seen_index", uid)
    pipe.zrem("last_seen_index", uid)
    pipe.delete(f"doc:{uid}", f"uid:{uid}", f"coverage:{uid}", f"contributions:{uid}")
    pipe.execute()
    for ip in ips:
        if not client.scard(f"ip:{ip}"):
            client.srem("all_ips", ip)


def delete_capture(raw, uid):
    """Controller deletion entry point; callers coordinate source retention."""
    with write_barrier():
        client = GenerationClient(raw, writable=True)
        before = load_document(client, uid)
        job = read_json(raw, "job")
        if job and job["phase"] != "done":
            raw.sadd(CONTROL + "deleted:" + job["id"], uid)
            raw.rpush(
                CONTROL + "journal:" + job["id"],
                json.dumps({"delete": uid, "before": before}),
            )
        remove_document(client, uid, before)


def queue_snapshot(raw, snapshot, full=False):
    """Polling committed SQL state repairs even a crash between save and enqueue."""
    # Desired inputs are one atomic value, independent of active generation data.
    # Connection setup and retries must never hold the capture publication barrier.
    pipe = raw.pipeline(transaction=True)
    pipe.set(CONTROL + "desired", json.dumps(snapshot, sort_keys=True))
    if full:
        pipe.set(CONTROL + "force_full", "1")
    pipe.execute()


def processing_revision(job):
    """Read either compact job metadata or the original inline snapshot format."""
    return job.get("snapshot_revision") or job.get("snapshot", {}).get("revision")


def reconciliation_status(raw):
    """Return public operational state, never rule bodies or source documents."""
    desired = read_json(raw, "desired", {})
    published = read_json(raw, "published", {})
    job = read_json(raw, "job", {})
    failure = read_json(raw, "failure", {})
    if failure:
        job = dict(job, **failure)
    pending = desired.get("revision") != published.get("revision")
    inputs = read_json(raw, "g:" + job["id"] + ":inputs", {}) if job.get("id") else {}
    processing = inputs.get("snapshot", job.get("snapshot", {}))
    pending_rules = (
        sum(
            processing.get("rules", {}).get(key) != desired.get("rules", {}).get(key)
            for key in set(processing.get("rules", {})) | set(desired.get("rules", {}))
        )
        if processing
        else len(desired.get("rules", {}))
    )
    phase = job.get("phase", "waiting_for_scheduler")
    if phase == "done" and pending:
        phase = "queued"
    elif not pending and published and phase in ("done", "waiting_for_scheduler"):
        phase = "up_to_date"
    return {
        "phase": phase,
        "processed": job.get("processed", 0),
        "total": job.get("total"),
        "revision": processing.get("revision", "")[:12],
        "pending_changes": pending_rules,
        "message": job.get("message", ""),
        "heartbeat": job.get("heartbeat"),
        "retry_at": job.get("retry_at"),
    }


def exact_anchor(client, criteria, coverage):
    """Select a positive indexed predicate only when its historical coverage is known."""
    anchors = []
    for field, values in criteria.items():
        if field.startswith("!") or "." in field or field in ("net", "http_headval"):
            continue
        for value in values if isinstance(values, list) else [values]:
            if (
                field == "http_header"
                and value not in coverage["HTTP_HEADER_COLLECTION"]
            ):
                continue
            key = f"{field}:{str(value).lower()}"
            anchors.append((client.scard(key), key))
    return min(anchors)[1] if anchors else None


class ReconciliationWorker:  # pylint: disable=too-many-instance-attributes
    """One resumable worker; supervisor owns start/stop and retry scheduling."""

    def __init__(self, raw, meili, batch_size=25, pause_seconds=0.1):
        self.raw = raw
        self.meili = meili
        self.batch_size = max(1, int(batch_size))
        self.pause_seconds = max(0.0, float(pause_seconds))
        self.stopping = False
        self.job = None
        self.plan = None
        self._inputs_saved = False

    def checkpoint(self, **changes):
        """Publish progress only after corresponding durable writes succeed."""
        self.job.update(changes, heartbeat=time.time())
        if "snapshot" in self.job and (
            "candidate_sources" in changes or not self._inputs_saved
        ):
            inputs = {
                key: self.job[key]
                for key in ("snapshot", "previous", "candidate_sources")
            }
            # Never persist a compact job before its frozen inputs. A failed
            # first checkpoint can itself enter the exception checkpoint path.
            pipe = self.raw.pipeline(transaction=True)
            pipe.set(
                CONTROL + "g:" + self.job["id"] + ":inputs",
                json.dumps(inputs, sort_keys=True),
            )
            pipe.set(
                CONTROL + "job", json.dumps(self.progress_record(), sort_keys=True)
            )
            pipe.execute()
            self._inputs_saved = True
        else:
            write_json(self.raw, "job", self.progress_record())

    def progress_record(self):
        """Keep large frozen definitions out of frequently updated counters."""
        return {
            key: value
            for key, value in self.job.items()
            if key not in ("snapshot", "previous", "candidate_sources")
        }

    def restore_job(self, job):
        """Restore frozen inputs, upgrading inline jobs without taking newer rules."""
        self.job = job
        inputs = read_json(self.raw, "g:" + job["id"] + ":inputs")
        if inputs is None:
            if "snapshot" not in job:
                raise SnapshotInvalid(
                    "Missing frozen reconciliation inputs; cannot resume this staging "
                    "generation. Queue a full rebuild with tag_mgmt.py reindex --allrules --flush."
                )
            inputs = {
                key: job.get(key)
                for key in ("snapshot", "previous", "candidate_sources")
            }
        else:
            self._inputs_saved = True
        job.update(inputs, snapshot_revision=inputs["snapshot"]["revision"])
        if "candidate_source" not in job:
            # Older jobs scanned all_uids directly. Replan in the same staging
            # generation and replay its retained journal from the beginning.
            job.update(
                candidate_sources=None,
                candidate_source=0,
                candidate_cursor=0,
                candidates_ready=False,
                cursor=0,
                pending_uids=[],
                scan_complete=False,
                journal_offset=0,
                processed=0,
            )
            self.raw.delete(
                CONTROL + "candidates:" + job["id"], CONTROL + "processed:" + job["id"]
            )
            self.checkpoint(candidate_sources=None)

    def start(self):
        """Resume immutable inputs or establish a new generation and journal."""
        with write_barrier(background=True):
            job = read_json(self.raw, "job")
            desired = read_json(self.raw, "desired", {})
            # Completed work and superseded blocked work need no resumption.
            # Inspect both historical formats before requiring separate inputs.
            if job and job["phase"] == "done":
                job = None
            if (
                job
                and job["phase"] == "blocked"
                and (
                    (
                        processing_revision(job)
                        and desired.get("revision") != processing_revision(job)
                    )
                    or self.raw.get(CONTROL + "force_full")
                )
            ):
                job = None
            if job:
                self.restore_job(job)
                if job["snapshot"]["code"] != code_revision():
                    raise SnapshotInvalid(
                        "Parser changed: resume with the original code before upgrading"
                    )
            else:
                snapshot = read_json(self.raw, "desired")
                previous = read_json(self.raw, "published")
                full = bool(self.raw.get(CONTROL + "force_full")) or not previous
                if not snapshot or (not full and previous == snapshot):
                    return False
                generation = uuid4().hex
                parent = self.raw.get(ACTIVE) or ""
                # Require COPY before activating any managed namespace.
                if not self.raw.execute_command("COMMAND", "INFO", "COPY"):
                    raise RuntimeError(
                        "Online index generations require Kvrocks COPY support"
                    )
                self.raw.set(f"{CONTROL}g:{generation}:parent", "-" if full else parent)
                self.job = {
                    "id": generation,
                    "parent": parent,
                    "snapshot": snapshot,
                    "snapshot_revision": snapshot["revision"],
                    "previous": previous,
                    "full": full,
                    "phase": "scanning",
                    "cursor": 0,
                    "pending_uids": [],
                    "scan_complete": False,
                    "journal_offset": 0,
                    "processed": 0,
                    "total": int(GenerationClient(self.raw, parent).scard("all_uids")),
                    "attempts": 0,
                    "candidate_sources": None,
                    "candidate_source": 0,
                    "candidate_cursor": 0,
                    "candidates_ready": False,
                }
                self.raw.delete(CONTROL + "force_full")
                self.checkpoint(candidate_sources=None)
        try:
            self.plan = RulePlan(self.job["snapshot"], self.job.get("previous"))
        except ValueError as error:
            raise SnapshotInvalid(str(error)) from error
        self.raw.delete(CONTROL + "failure")
        self.checkpoint(
            message="",
            retry_at=None,
            phase="scanning" if not self.job["scan_complete"] else "catching_up",
        )
        return True

    def candidate_sources(self):
        """Use proven exact positive anchors; otherwise retain the full scope."""
        if self.job["full"]:
            return ["all_uids", "@meili"]
        previous = self.job.get("previous") or {}
        if previous.get("code") != self.job["snapshot"]["code"]:
            return ["all_uids"]
        if previous.get("parser") != self.job["snapshot"]["parser"]:
            return ["all_uids"]
        client = GenerationClient(self.raw, self.job["parent"])
        sources = set()
        changed = self.plan.changed | (
            set(previous.get("rules", {})) - set(self.plan.rules)
        )
        for rule_id in changed:
            sources.add(f"rule_matches:{rule_id}")
            if rule_id not in self.plan.rules:
                continue
            for criteria in iter_criteria(self.plan.rules[rule_id]["criteria_groups"]):
                if any(
                    field.removeprefix("!").split(".")[0] == "tag" for field in criteria
                ):
                    return ["all_uids"]
                anchor = exact_anchor(client, criteria, previous["parser"])
                if anchor is None:
                    return ["all_uids"]
                sources.add(anchor)
        return sorted(sources)

    def prepare_candidates_batch(self):
        """Build a resumable UID set; ingestion during planning is journaled."""
        if self.job["candidate_sources"] is None:
            self.checkpoint(
                candidate_sources=self.candidate_sources(), phase="planning", total=None
            )
        sources = self.job["candidate_sources"]
        position = self.job["candidate_source"]
        if position >= len(sources):
            total = int(self.raw.scard(CONTROL + "candidates:" + self.job["id"]))
            self.checkpoint(
                candidates_ready=True,
                phase="scanning",
                total=total,
                planned_total=total,
            )
            return
        key = sources[position]
        cursor = self.job["candidate_cursor"]
        if key == "@meili":
            page = self.meili.get_documents(
                {"offset": cursor, "limit": self.batch_size, "fields": ["id"]}
            )
            values = [str(dict(item)["id"]) for item in page.results]
            next_cursor = cursor + len(values) if len(values) == self.batch_size else 0
        else:
            client = GenerationClient(self.raw, self.job["parent"])
            next_cursor, values = client.sscan(
                key, cursor=cursor, count=self.batch_size
            )
        if values:
            self.raw.sadd(CONTROL + "candidates:" + self.job["id"], *values)
        self.checkpoint(
            candidate_cursor=int(next_cursor),
            candidate_source=position if next_cursor else position + 1,
        )

    def process_uid(self, uid):
        """Fetch source outside the write barrier; replays cover concurrent edits."""
        if self.raw.sismember(CONTROL + "deleted:" + self.job["id"], uid):
            self.raw.sadd(CONTROL + "processed:" + self.job["id"], uid)
            return
        base = GenerationClient(self.raw, self.job["parent"])
        document = load_document(base, uid)
        profile_id = base.get(f"coverage:{uid}")
        profile = read_json(self.raw, "coverage:" + profile_id) if profile_id else None
        reparse = self.job["full"] or not self.plan.covered(profile)
        self.job["phase"] = "reparsing" if reparse else "retagging"
        if reparse:
            source = self.meili.get_document(uid)
            source = source if isinstance(source, dict) else vars(source)
            parsed = parsed_source(source, self.job["snapshot"])
            # Meilisearch does not contain accumulated historical timestamps.
            merge_history(parsed, document)
            document = parsed
        values = base.get(f"contributions:{uid}")
        previous = json.loads(values) if values is not None else None
        tags, contributions = self.plan.evaluate(document, previous, force=reparse)
        document["tag"] = tags
        target = GenerationClient(self.raw, self.job["id"], writable=True)
        with write_barrier(background=True):
            save_document(
                target, document, contributions, self.job["snapshot"], full=reparse
            )
            self.raw.sadd(CONTROL + "processed:" + self.job["id"], uid)

    def scan_batch(self):
        """SSCAN is advisory; persist its remainder before consuming bounded work."""
        if not self.job["pending_uids"]:
            cursor, uids = self.raw.sscan(
                CONTROL + "candidates:" + self.job["id"],
                self.job["cursor"],
                count=self.batch_size,
            )
            self.checkpoint(
                cursor=int(cursor), pending_uids=list(uids), scan_complete=not cursor
            )
        pending = self.job["pending_uids"]
        completed = 0
        for uid in pending[: self.batch_size]:
            if self.stopping:
                break
            self.process_uid(uid)
            completed += 1
        self.checkpoint(
            pending_uids=pending[completed:],
            processed=int(self.raw.scard(CONTROL + "processed:" + self.job["id"])),
        )

    def replay_batch(self):
        """Bound catch-up; publication barrier runs only when the backlog is empty."""
        key = CONTROL + "journal:" + self.job["id"]
        offset = self.job["journal_offset"]
        entries = self.raw.lrange(key, offset, offset + self.batch_size - 1)
        for serialized in entries:
            if self.stopping:
                return False
            entry = json.loads(serialized)
            if "delete" in entry:
                target = GenerationClient(self.raw, self.job["id"], writable=True)
                with write_barrier(background=True):
                    remove_document(target, entry["delete"], entry["before"])
                    self.checkpoint(journal_offset=self.job["journal_offset"] + 1)
                continue
            document = parsed_source(entry["source"], self.job["snapshot"])
            before = entry["before"]
            merge_history(document, before)
            tags, contributions = self.plan.evaluate(document, force=True)
            document["tag"] = tags
            target = GenerationClient(self.raw, self.job["id"], writable=True)
            with write_barrier(background=True):
                save_document(
                    target, document, contributions, self.job["snapshot"], old=before
                )
                self.checkpoint(journal_offset=self.job["journal_offset"] + 1)
        if entries:
            return False
        with write_barrier(background=True):
            if self.raw.llen(key) != self.job["journal_offset"]:
                return False
            if (
                int(self.raw.scard(CONTROL + "processed:" + self.job["id"]))
                != self.job["planned_total"]
            ):
                raise RuntimeError(
                    "Candidate processing is incomplete; refusing publication"
                )
            if (self.raw.get(ACTIVE) or "") != self.job["parent"]:
                raise RuntimeError("Active generation changed outside reconciliation")
            self.job.update(phase="done", message="", heartbeat=time.time())
            pipe = self.raw.pipeline(transaction=True)
            pipe.set(ACTIVE, self.job["id"])
            pipe.set(
                CONTROL + "published", json.dumps(self.job["snapshot"], sort_keys=True)
            )
            pipe.set(
                CONTROL + "job", json.dumps(self.progress_record(), sort_keys=True)
            )
            pipe.execute()
        return True

    def run(self):
        """Run to completion or graceful stop, checkpointing failures for retry."""
        with file_lock(state_directory() / "worker.lock", blocking=False):
            try:
                if not self.start():
                    return
                while not self.stopping:
                    parent_pid = os.environ.get("PLUM_INDEX_PARENT_PID")
                    if parent_pid and os.getppid() != int(parent_pid):
                        self.stopping = True
                        break
                    if not self.job["candidates_ready"]:
                        self.prepare_candidates_batch()
                    elif self.job["pending_uids"] or not self.job["scan_complete"]:
                        self.scan_batch()
                    else:
                        self.checkpoint(phase="catching_up", total=None)
                        if self.replay_batch():
                            return
                    time.sleep(self.pause_seconds)
                self.checkpoint(phase="paused", message="Stopped after checkpoint")
            except Exception as error:
                if self.job:
                    # EXEC may commit before its response is lost. Do not turn a
                    # successful atomic publication back into a failed job.
                    if self.raw.get(ACTIVE) == self.job["id"]:
                        return
                    attempts = self.job.get("attempts", 0) + 1
                    invalid = isinstance(error, SnapshotInvalid)
                    self.checkpoint(
                        phase="blocked" if invalid else "failed",
                        attempts=attempts,
                        message=(
                            str(error)
                            if invalid
                            else "Index update failed; retained active generation. Check worker logs."
                        ),
                        retry_at=time.time() + min(3600, 30 * 2 ** min(attempts, 7)),
                    )
                    # A previous startup failure must not mask this job's
                    # actionable blocked/error status indefinitely.
                    self.raw.delete(CONTROL + "failure")
                else:
                    write_json(
                        self.raw,
                        "failure",
                        {
                            "phase": "failed",
                            "retry_at": time.time() + 60,
                            "message": "Unable to start indexing; check backend capabilities and worker logs.",
                        },
                    )
                raise
