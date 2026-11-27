"""Durable background reconciliation and the common ingestion write barrier."""

import json
import logging
import os
import time
from contextlib import contextmanager, ExitStack
from pathlib import Path
from uuid import uuid4

try:
    from .kvrocks import KVrocksIndexer
    from .search_query import iter_criteria
    from .scan_ports import build_scan_port, queue_scan_port, read_scan_ports
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
    from scan_ports import build_scan_port, queue_scan_port, read_scan_ports
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
    "nodata",
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
CAPTURE_FIELDS = tuple(field for field in FIELDS if field not in {"tag", "engine"})

logger = logging.getLogger(__name__)
DESIRED = CONTROL + "desired"
DESIRED_REVISION = CONTROL + "desired_revision"
RETAG_POLL_SECONDS = 0.25


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


def load_document(client, uid, *, preserve_storage=False):
    """Reconstruct normalized fields and accumulated timestamps in one batch."""
    pipe = client.pipeline(transaction=False)
    pipe.hgetall(f"doc:{uid}")
    for field in FIELDS:
        pipe.smembers(f"{field}s:{uid}")
    pipe.get(f"contributions:{uid}")
    values = pipe.execute()
    document = dict(values[0], uid=uid, id=uid)
    document.update({field: sorted(items) for field, items in zip(FIELDS, values[1:])})
    if not preserve_storage:
        document.pop("nse_marker", None)
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


def unchanged_capture_fields(before, document):
    """Compare the structural values the full Kvrocks writer would store."""
    if before.get("ip") != document["ip"] or "nse_marker" in before:
        return False
    first_seen, last_seen = KVrocksIndexer.merged_seen_range(before, document)
    if first_seen is not None and (
        before.get("first_seen") != str(first_seen)
        or before.get("last_seen") != str(last_seen)
    ):
        return False
    engines = document.get("engine") or []
    if isinstance(engines, str):
        engines = [engines]
    stored_engine = (
        ["masscan"]
        if any(str(value).strip().lower() == "masscan" for value in engines)
        else []
    )
    return before["engine"] == stored_engine and all(
        set(before[field])
        == {value.lower() for value in document.get(field, []) if value}
        for field in CAPTURE_FIELDS
    )


def queue_capture_coverage(raw, pipe, uid, snapshot, rule_drift):
    """Store the shared coverage profile before linking the capture to it."""
    profile = coverage_profile(snapshot)
    if rule_drift:
        profile["rule_revision"] = snapshot["revision"]
    profile_id = fingerprint(profile)
    raw.set(
        CONTROL + "coverage:" + profile_id,
        json.dumps(profile, sort_keys=True),
        nx=True,
    )
    pipe.set(f"coverage:{uid}", profile_id)
    if rule_drift is not None:
        update_drift = pipe.sadd if rule_drift else pipe.srem
        update_drift("rule_drift", uid)


def save_reparse_delta(client, document, contributions, snapshot, before, rule_drift):
    """Inherit the capture fields and apply tag and rule membership differences."""
    uid = document["uid"]
    old_tags = set(before["tag"])
    tags = {tag.lower() for tag in document["tag"] if tag}
    old_contributions = before["_contributions"]
    pipe = client.pipeline()
    for tag in sorted(old_tags - tags):
        pipe.srem(f"tags:{uid}", tag)
        pipe.srem(f"tag:{tag}", uid)
    for tag in sorted(tags - old_tags):
        pipe.sadd(f"tags:{uid}", tag)
        pipe.sadd(f"tag:{tag}", uid)
    for rule_id in sorted(old_contributions.keys() - contributions.keys()):
        pipe.srem(f"rule_matches:{rule_id}", uid)
    for rule_id in sorted(contributions.keys() - old_contributions.keys()):
        pipe.sadd(f"rule_matches:{rule_id}", uid)
    if old_contributions != contributions:
        pipe.set(f"contributions:{uid}", json.dumps(contributions, sort_keys=True))
    if tags:
        pipe.sadd(KVrocksIndexer.TAG_CATALOGUE_KEY, *sorted(tags))
    if "scan_port" in document:
        queue_scan_port(pipe, uid, document["scan_port"])
    queue_capture_coverage(client.raw, pipe, uid, snapshot, rule_drift)
    pipe.execute()


def save_document(
    client, document, contributions, snapshot, *, old=None, full=True, rule_drift=None
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
    if full or rule_drift is not None:
        queue_capture_coverage(client.raw, pipe, uid, snapshot, rule_drift)
    if "scan_port" in document:
        queue_scan_port(pipe, uid, document["scan_port"])
    pipe.set(f"contributions:{uid}", json.dumps(contributions, sort_keys=True))
    pipe.execute()


def ingest_sources(raw, sources, fallback_snapshot, *, live_snapshot=None):
    """Journal before changing the active index; export retry remains idempotent."""
    plan = None
    generation = None
    for source in sources:
        while True:
            active = raw.get(ACTIVE) or ""
            if plan is None or generation != active:
                published = read_json(raw, "published", fallback_snapshot)
                snapshot = live_snapshot or published
                journal_live_rules = live_snapshot is not None
                try:
                    plan = RulePlan(snapshot)
                except ValueError:
                    if snapshot == published:
                        raise
                    logger.warning(
                        "New detection rules are invalid; continuing ingestion with published rules",
                        exc_info=True,
                    )
                    plan = RulePlan(published)
                    snapshot = published
                    journal_live_rules = False
                generation = active
                rule_drift = snapshot.get("revision") != published.get("revision")
            else:
                snapshot = plan.snapshot
            document = parsed_source(source, snapshot)
            tags, contributions = plan.evaluate(document, force=True, source=source)
            document["tag"] = tags
            document["scan_port"] = build_scan_port(
                source, document, plan, contributions=contributions
            )
            with write_barrier():
                if (raw.get(ACTIVE) or "") != generation:
                    continue
                _ingest_document(
                    raw,
                    source,
                    generation,
                    snapshot,
                    document,
                    contributions,
                    rule_drift=rule_drift,
                    journal_live_rules=journal_live_rules,
                )
            break


def _ingest_document(
    raw,
    source,
    generation,
    snapshot,
    document,
    contributions,
    *,
    rule_drift,
    journal_live_rules,
):  # pylint: disable=too-many-arguments
    """Journal and write one precomputed capture under the barrier."""
    client = GenerationClient(raw, generation, writable=True)
    job = read_json(raw, "job")
    uid = document["uid"]
    old = load_document(client, uid)
    if job and job["phase"] != "done":
        journal = journal_id(job)
        raw.srem(CONTROL + "deleted:" + journal, uid)
        entry = {"source": source, "before": old}
        if journal_live_rules and snapshot["revision"] != processing_revision(job):
            revision = snapshot["revision"]
            rules_key = CONTROL + "journal_rules:" + journal
            if not raw.hexists(rules_key, revision):
                raw.hset(rules_key, revision, json.dumps(snapshot, sort_keys=True))
            entry["rule_revision"] = revision
        raw.rpush(CONTROL + "journal:" + journal, json.dumps(entry))
    save_document(client, document, contributions, snapshot, rule_drift=rule_drift)


def ingest_indexer_sources(indexer, sources, *, live_snapshot=None):
    """Use the managed writer when enabled; leave legacy adapters unchanged."""
    if getattr(indexer, "accepts_source_documents", False) is not True:
        return False
    desired = read_json(indexer.raw, "desired") or live_snapshot
    if desired is None:
        return False
    ingest_sources(
        indexer.raw, sources, desired, live_snapshot=live_snapshot or desired
    )
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
    pipe.srem("rule_drift", uid)
    pipe.zrem("first_seen_index", uid)
    pipe.zrem("last_seen_index", uid)
    queue_scan_port(pipe, uid, None)
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
            journal = journal_id(job)
            raw.sadd(CONTROL + "deleted:" + journal, uid)
            raw.rpush(
                CONTROL + "journal:" + journal,
                json.dumps({"delete": uid, "before": before}),
            )
        remove_document(client, uid, before)


def queue_snapshot(raw, snapshot, full=False):
    """Polling committed SQL state repairs even a crash between save and enqueue."""
    # Serialize with cutover without taking the capture write barrier.
    with file_lock(state_directory() / "desired.lock"):
        pipe = raw.pipeline(transaction=True)
        pipe.set(DESIRED, json.dumps(snapshot, sort_keys=True))
        pipe.set(DESIRED_REVISION, snapshot["revision"])
        if full:
            pipe.set(CONTROL + "force_full", "1")
        pipe.execute()


def journal_id(job):
    """Find the journal retained across replacement of a staging generation."""
    return job.get("journal_id", job["id"])


def processing_revision(job):
    """Read either compact job metadata or the original inline snapshot format."""
    return job.get("snapshot_revision") or job.get("snapshot", {}).get("revision")


def has_rule_drift(raw):
    """Detect reports tagged ahead of the published rules, including after a revert."""
    return bool(GenerationClient(raw).scard("rule_drift"))


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
    if not pending and published and phase in ("done", "waiting_for_scheduler"):
        pending = has_rule_drift(raw)
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
        if (
            field.startswith("!")
            or "." in field
            or field in ("net", "http_headval", "nse_body")
        ):
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
        self._journal_plan = None
        self._inputs_saved = False
        self._retag_check_at = 0
        self._retag_superseded = False
        self._delta_journal_checkpoint = None

    def checkpoint(self, *, new_job=False, **changes):
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
            # creation leaves the old job and its journal visible to ingestion.
            pipe = self.raw.pipeline(transaction=True)
            if new_job:
                pipe.set(
                    f"{CONTROL}g:{self.job['id']}:parent",
                    "-" if self.job["full"] else self.job["parent"],
                )
                pipe.delete(CONTROL + "force_full")
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

    def _fast_retag(self):
        """Classify by the frozen plan and source reads, including resumed jobs."""
        previous = self.job.get("previous")
        current = self.job["snapshot"]
        return (
            previous
            and not self.job["full"]
            and not self.job.get("uses_meilisearch", False)
            and self.job["phase"] != "reparsing"
            and previous["code"] == current["code"]
            and previous["parser"] == current["parser"]
            and not self.plan.needs_nse_source(previous={})
        )

    def _newer_rule_revision(self, desired):
        """Allow supersession only while both targets have the same parser."""
        current = self.job["snapshot"]
        return (
            desired
            and desired["revision"] != current["revision"]
            and desired["code"] == current["code"]
            and desired["parser"] == current["parser"]
        )

    def retag_pending(self, *, checkpoint=False):
        """Poll compact revision metadata at checkpoints and during pacing waits."""
        if not self._fast_retag():
            return False
        now = time.monotonic()
        if checkpoint or now >= self._retag_check_at:
            self._retag_check_at = now + RETAG_POLL_SECONDS
            revision = self.raw.get(DESIRED_REVISION)
            self._retag_superseded = (
                revision is not None
                and revision != processing_revision(self.job)
                and self._newer_rule_revision(read_json(self.raw, "desired"))
            )
        return self._retag_superseded

    def _create_job(self, snapshot, previous, force_full, replaced):
        """Install a staging generation and attach the old journal atomically."""
        parent = self.raw.get(ACTIVE) or ""
        if not self.raw.execute_command("COMMAND", "INFO", "COPY"):
            raise RuntimeError("Online index generations require Kvrocks COPY support")
        full = force_full or not previous
        job = {
            "id": uuid4().hex,
            "parent": parent,
            "snapshot": snapshot,
            "snapshot_revision": snapshot["revision"],
            "previous": previous,
            "full": full,
            "ordered_candidates": not full,
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
        if replaced:
            journal = journal_id(replaced)
            job.update(
                journal_id=journal,
                journal_rebase_until=self.raw.llen(CONTROL + "journal:" + journal),
            )
        self.job = job
        try:
            self.checkpoint(new_job=True, candidate_sources=None)
        except Exception:
            # The transaction may have committed before losing its reply. Reload
            # durable state on retry instead of checkpointing either job here.
            self.job = None
            raise

    def start(self, *, supersede=False):
        """Resume immutable inputs or establish a new generation and journal."""
        self._inputs_saved = False
        self._journal_plan = None
        self._retag_check_at = 0
        self._retag_superseded = False
        with write_barrier(background=True), file_lock(
            state_directory() / "desired.lock"
        ):
            job = read_json(self.raw, "job")
            desired = read_json(self.raw, "desired", {})
            force_full = bool(self.raw.get(CONTROL + "force_full"))
            if job and job["phase"] == "done":
                job = None
            replace_blocked = (
                job
                and job["phase"] == "blocked"
                and (
                    (
                        processing_revision(job)
                        and desired.get("revision") != processing_revision(job)
                    )
                    or force_full
                )
            )
            replace_fast = (
                supersede and self._fast_retag() and self._newer_rule_revision(desired)
            )
            if job and not (replace_blocked or replace_fast):
                self.restore_job(job)
                if job["snapshot"]["code"] != code_revision():
                    raise SnapshotInvalid(
                        "Parser changed: resume with the original code before upgrading"
                    )
            else:
                previous = read_json(self.raw, "published")
                if not desired or (
                    not job
                    and not force_full
                    and previous == desired
                    and not has_rule_drift(self.raw)
                ):
                    return False
                self._create_job(desired, previous, force_full, job)
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
        sources = {"rule_drift"}
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

    def candidate_count(self):
        """Count planned candidates in the current or legacy queue format."""
        count = self.raw.zcard if self.job.get("ordered_candidates") else self.raw.scard
        return int(count(CONTROL + "candidates:" + self.job["id"]))

    def prepare_candidates_batch(self):
        """Plan UID batches; incremental work uses the existing timestamp index."""
        if self.job["candidate_sources"] is None:
            self.checkpoint(
                candidate_sources=self.candidate_sources(), phase="planning", total=None
            )
        sources = self.job["candidate_sources"]
        position = self.job["candidate_source"]
        if position >= len(sources):
            total = self.candidate_count()
            self.checkpoint(
                candidates_ready=True,
                phase="scanning",
                total=total,
                planned_total=total,
            )
            return
        key = sources[position]
        cursor = self.job["candidate_cursor"]
        client = GenerationClient(self.raw, self.job["parent"])
        if key == "@meili":
            page = self.meili.get_documents(
                {"offset": cursor, "limit": self.batch_size, "fields": ["id"]}
            )
            values = [str(dict(item)["id"]) for item in page.results]
            next_cursor = cursor + len(values) if len(values) == self.batch_size else 0
        else:
            next_cursor, values = client.sscan(
                key, cursor=cursor, count=self.batch_size
            )
        if values:
            candidates = CONTROL + "candidates:" + self.job["id"]
            if self.job.get("ordered_candidates"):
                timestamp_key = client.resolve_many(["last_seen_index"])[
                    "last_seen_index"
                ]
                timestamps = self.raw.zmscore(timestamp_key, values)
                self.raw.zadd(
                    candidates,
                    {
                        uid: stamp if stamp is not None else "-inf"
                        for uid, stamp in zip(values, timestamps)
                    },
                    nx=True,
                )
            else:
                self.raw.sadd(candidates, *values)
        self.checkpoint(
            candidate_cursor=int(next_cursor),
            candidate_source=position if next_cursor else position + 1,
        )

    def process_uid(self, uid):
        """Fetch source outside the write barrier; replays cover concurrent edits."""
        if self.raw.sismember(CONTROL + "deleted:" + journal_id(self.job), uid):
            self.raw.sadd(CONTROL + "processed:" + self.job["id"], uid)
            return
        base = GenerationClient(self.raw, self.job["parent"])
        profile_id = base.get(f"coverage:{uid}")
        profile = read_json(self.raw, "coverage:" + profile_id) if profile_id else None
        rule_drift = bool(profile and profile.get("rule_revision"))
        reparse = self.job["full"] or not self.plan.covered(profile)
        values = base.get(f"contributions:{uid}")
        previous = json.loads(values) if values is not None else None
        can_compare = (
            reparse
            and bool(profile and profile.get("code"))
            and previous is not None
            and self._delta_journal_checkpoint is not None
        )
        document = (
            load_document(base, uid, preserve_storage=True)
            if can_compare
            else load_document(base, uid)
        )
        force = reparse or rule_drift
        previous_port = None if reparse else read_scan_ports(base, [uid]).get(uid)
        needs_source = reparse or self.plan.needs_nse_source(previous, force)
        self.job["phase"] = "reparsing" if needs_source else "retagging"
        source = None
        if needs_source:
            self.job["uses_meilisearch"] = True
            source = self.meili.get_document(uid)
            source = source if isinstance(source, dict) else vars(source)
        before = None
        if reparse:
            parsed = parsed_source(source, self.job["snapshot"])
            # Meilisearch does not contain accumulated historical timestamps.
            merge_history(parsed, document)
            if can_compare and unchanged_capture_fields(document, parsed):
                before = document
            document = parsed
        tags, contributions = self.plan.evaluate(
            document, previous, force=force, source=source
        )
        document["tag"] = tags
        if source is not None or previous_port is not None:
            document["scan_port"] = build_scan_port(
                source, document, self.plan, previous_port, contributions=contributions
            )
        target = GenerationClient(self.raw, self.job["id"], writable=True)
        clear_drift = False if rule_drift else None
        with write_barrier(background=True):
            if before is not None and self._can_save_reparse_delta(target, uid):
                save_reparse_delta(
                    target,
                    document,
                    contributions,
                    self.job["snapshot"],
                    before,
                    clear_drift,
                )
            else:
                save_document(
                    target,
                    document,
                    contributions,
                    self.job["snapshot"],
                    full=reparse,
                    rule_drift=clear_drift,
                )
            self.raw.sadd(CONTROL + "processed:" + self.job["id"], uid)

    def _can_save_reparse_delta(self, target, uid):
        """Reject a changed parent or a capture already written in this staging job."""
        journal, offset = self._delta_journal_checkpoint
        pipe = self.raw.pipeline(transaction=False)
        pipe.llen(journal)
        pipe.smismember(
            target.owned(target.generation),
            [
                f"{field}:{uid}"
                for field in ("doc", "tags", "contributions", "coverage")
            ],
        )
        current_offset, staged = pipe.execute()
        return current_offset == offset and not any(staged)

    def _claim_candidates(self):
        """Persist the newest batch and dequeue it in the same transaction."""
        key = CONTROL + "candidates:" + self.job["id"]
        if self.job.get("ordered_candidates"):
            uids = self.raw.zrevrange(key, 0, self.batch_size - 1)
            if not uids:
                self.checkpoint(scan_complete=True)
                return
            self.job.update(pending_uids=uids, heartbeat=time.time())
            pipe = self.raw.pipeline(transaction=True)
            pipe.zrem(key, *uids)
            pipe.set(
                CONTROL + "job", json.dumps(self.progress_record(), sort_keys=True)
            )
            try:
                pipe.execute()
            except Exception:
                # Retry must reload the queue and checkpoint together after an
                # uncertain EXEC reply.
                self.job = None
                raise
        else:
            cursor, uids = self.raw.sscan(
                key, self.job["cursor"], count=self.batch_size
            )
            self.checkpoint(
                cursor=int(cursor), pending_uids=list(uids), scan_complete=not cursor
            )

    def scan_batch(self):
        """Process a bounded batch, resuming any claimed work first."""
        if not self.job["pending_uids"]:
            self._claim_candidates()
        pending = self.job["pending_uids"]
        batch = pending[: self.batch_size]
        done = (
            self.raw.smismember(CONTROL + "processed:" + self.job["id"], batch)
            if batch and self.job.get("ordered_candidates")
            else [False] * len(batch)
        )
        if batch and not self.job["full"]:
            journal = CONTROL + "journal:" + journal_id(self.job)
            # Take the starting offset between foreground writes. Every later
            # parent mutation must append to this journal before writing.
            with write_barrier(background=True):
                self._delta_journal_checkpoint = (journal, self.raw.llen(journal))
        completed = 0
        try:
            for uid, already_done in zip(batch, done):
                if self.stopping:
                    break
                if not already_done:
                    self.process_uid(uid)
                completed += 1
        finally:
            self._delta_journal_checkpoint = None
        self.checkpoint(
            pending_uids=pending[completed:],
            processed=int(self.raw.scard(CONTROL + "processed:" + self.job["id"])),
        )

    def _plan_for_journal(self, revision):
        """Keep a live report's rules when an older historical revision publishes."""
        if not revision or revision == self.plan.snapshot["revision"]:
            return self.plan
        if (
            self._journal_plan is None
            or self._journal_plan.snapshot["revision"] != revision
        ):
            key = CONTROL + "journal_rules:" + journal_id(self.job)
            serialized = self.raw.hget(key, revision)
            if serialized is None:
                raise SnapshotInvalid("Missing rule snapshot for a journaled capture")
            self._journal_plan = RulePlan(json.loads(serialized))
        return self._journal_plan

    def replay_batch(self):
        """Bound catch-up; publication barrier runs only when the backlog is empty."""
        key = CONTROL + "journal:" + journal_id(self.job)
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
            plan = self.plan
            if self.job["journal_offset"] >= self.job.get("journal_rebase_until", 0):
                plan = self._plan_for_journal(entry.get("rule_revision"))
            snapshot = plan.snapshot
            document = parsed_source(entry["source"], snapshot)
            before = entry["before"]
            merge_history(document, before)
            tags, contributions = plan.evaluate(
                document, force=True, source=entry["source"]
            )
            document["tag"] = tags
            document["scan_port"] = build_scan_port(
                entry["source"], document, plan, contributions=contributions
            )
            target = GenerationClient(self.raw, self.job["id"], writable=True)
            with write_barrier(background=True):
                save_document(
                    target,
                    document,
                    contributions,
                    snapshot,
                    old=before,
                    rule_drift=snapshot["revision"] != self.job["snapshot"]["revision"],
                )
                self.checkpoint(journal_offset=self.job["journal_offset"] + 1)
        if entries:
            return False
        with write_barrier(background=True), file_lock(
            state_directory() / "desired.lock"
        ):
            if self._fast_retag() and self._newer_rule_revision(
                read_json(self.raw, "desired")
            ):
                self._retag_superseded = True
                self._retag_check_at = time.monotonic() + RETAG_POLL_SECONDS
                return False
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

    def _record_worker_failure(self, error):
        """Persist the failure without rewriting an uncertain checkpoint."""
        if not self.job:
            write_json(
                self.raw,
                "failure",
                {
                    "phase": "failed",
                    "retry_at": time.time() + 60,
                    "message": "Unable to start indexing; check backend capabilities and worker logs.",
                },
            )
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
        # A previous startup failure must not mask this job's blocked status.
        self.raw.delete(CONTROL + "failure")

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
                    if self._retag_superseded or self.retag_pending(checkpoint=True):
                        if not self.start(supersede=True):
                            return
                        continue
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
                if self.job and self.raw.get(ACTIVE) == self.job["id"]:
                    return
                self._record_worker_failure(error)
                raise
