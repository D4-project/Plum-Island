#!/usr/bin/env python3
"""Recover Meilisearch documents still referenced by Kvrocks."""

import argparse
import copy
import csv
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

try:
    from .split_meili_dump_by_port import (
        add_port_hash,
        port_document_uuid,
        strip_port_hash,
    )
except ImportError:
    from split_meili_dump_by_port import (
        add_port_hash,
        port_document_uuid,
        strip_port_hash,
    )


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DEFAULT_CONFIG_FILE = PROJECT_DIR / "webapp" / "config.py"
DEFAULT_REPORT_FILE = Path("missing_meili_reintegration.csv")
DEFAULT_BATCH_SIZE = 250
DEFAULT_TASK_TIMEOUT_MS = 900_000
TASK_STATUS_INTERVAL_SECONDS = 30
TASK_POLL_INTERVAL_SECONDS = 1


class ReintegrationError(RuntimeError):
    """Raised when a Meilisearch reintegration task fails."""


class MeiliTaskFailed(ReintegrationError):
    """Raised when a Meilisearch task reaches a failed terminal state."""

    def __init__(self, task_uid, status, error):
        self.task_uid = task_uid
        super().__init__(
            f"Meilisearch task {task_uid} ended with status "
            f"{status or 'unknown'}: {error or 'no error details'}"
        )


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Find Kvrocks UIDs missing from Meilisearch, recover them from "
            "raw job JSON files, and optionally reinsert them."
        )
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_FILE),
        help=f"Runtime Python config. Default: {DEFAULT_CONFIG_FILE}",
    )
    parser.add_argument(
        "--json-folder",
        default=None,
        help="Override JSON_FOLDER from runtime config.",
    )
    parser.add_argument(
        "--index-name",
        default="plum",
        help="Meilisearch index name. Default: plum",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Meilisearch read/write batch size. Default: {DEFAULT_BATCH_SIZE}",
    )
    parser.add_argument(
        "--task-timeout-ms",
        type=int,
        default=DEFAULT_TASK_TIMEOUT_MS,
        help=(
            "Maximum wait per Meilisearch write task in milliseconds. "
            f"Default: {DEFAULT_TASK_TIMEOUT_MS}"
        ),
    )
    parser.add_argument(
        "--report",
        default=str(DEFAULT_REPORT_FILE),
        help=f"CSV report path. Default: {DEFAULT_REPORT_FILE}",
    )
    work_database = parser.add_mutually_exclusive_group()
    work_database.add_argument(
        "--work-db",
        default=None,
        help=(
            "New SQLite work DB path. It is preserved for resume if the run fails. "
            "Default: temporary file."
        ),
    )
    work_database.add_argument(
        "--resume-work-db",
        default=None,
        help="Resume reintegration from a work DB preserved by a failed apply run.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10_000,
        help="Print raw-file progress every N files. Default: 10000",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Add recovered missing documents to Meilisearch. Default: dry-run.",
    )
    return parser.parse_args()


def load_runtime_config(config_path):
    """Load webapp/config.py without importing the Flask application."""
    config_path = Path(config_path).resolve()
    spec = importlib.util.spec_from_file_location("plum_runtime_config", config_path)
    if spec is None or spec.loader is None:
        raise ReintegrationError(f"Unable to load config: {config_path}")
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    return config


def create_work_database(work_db_path=None):
    """Create disk-backed candidate storage and return connection/path/temp flag."""
    temporary = work_db_path is None
    if temporary:
        with tempfile.NamedTemporaryFile(
            prefix="plum_missing_meili_",
            suffix=".sqlite",
            delete=False,
        ) as file_handle:
            work_path = Path(file_handle.name)
    else:
        work_path = Path(work_db_path).resolve()
        work_path.parent.mkdir(parents=True, exist_ok=True)
        if work_path.exists():
            raise ReintegrationError(
                f"Work DB already exists; choose a new --work-db path: {work_path}"
            )

    connection = sqlite3.connect(work_path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("""
        CREATE TABLE candidates (
            uid TEXT PRIMARY KEY,
            ip TEXT,
            first_seen TEXT,
            last_seen TEXT,
            source_path TEXT,
            source_seen REAL,
            source_mtime REAL,
            document_json TEXT,
            reintegrated INTEGER NOT NULL DEFAULT 0,
            task_uid INTEGER
        )
        """)
    connection.commit()
    return connection, work_path, temporary


def open_work_database(work_db_path):
    """Open and validate an existing reintegration work database."""
    work_path = Path(work_db_path).resolve()
    if not work_path.is_file():
        raise ReintegrationError(f"Work DB not found: {work_path}")
    connection = sqlite3.connect(work_path)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(candidates)").fetchall()
    }
    required_columns = {"uid", "document_json", "reintegrated", "task_uid"}
    if not required_columns.issubset(columns):
        connection.close()
        raise ReintegrationError(
            f"Invalid or incompatible reintegration work DB: {work_path}"
        )
    return connection, work_path


def chunked(iterable, chunk_size):
    """Yield lists of at most chunk_size items."""
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= chunk_size:
            yield batch
            batch = []
    if batch:
        yield batch


def snapshot_kvrocks_uids(kvrocks, connection, scan_count=5000):
    """Store every Kvrocks UID as an initial missing-document candidate."""
    inserted = 0
    uid_iterator = (
        str(uid) for uid in kvrocks.sscan_iter("all_uids", count=scan_count)
    )
    for uid_batch in chunked(uid_iterator, 5000):
        connection.executemany(
            "INSERT OR IGNORE INTO candidates(uid) VALUES (?)",
            ((uid,) for uid in uid_batch),
        )
        connection.commit()
        inserted += len(uid_batch)
        if inserted % 100_000 == 0:
            print(f"Loaded {inserted} Kvrocks UIDs", flush=True)
    return inserted


def meili_document_id(document):
    """Extract one document ID from SDK dict-like response objects."""
    document_id = getattr(document, "id", None)
    if document_id is None:
        document_id = dict(document).get("id")
    return str(document_id) if document_id not in (None, "") else None


def remove_present_meili_uids(index, connection, batch_size):
    """Stream Meilisearch IDs and remove them from candidate storage."""
    offset = 0
    processed = 0
    total = None
    while True:
        page = index.get_documents(
            {
                "limit": batch_size,
                "offset": offset,
                "fields": ["id"],
            }
        )
        results = list(getattr(page, "results", []) or [])
        if total is None:
            total = getattr(page, "total", None)
        if not results:
            break

        document_ids = [
            document_id
            for document_id in (meili_document_id(item) for item in results)
            if document_id
        ]
        connection.executemany(
            "DELETE FROM candidates WHERE uid = ?",
            ((document_id,) for document_id in document_ids),
        )
        connection.commit()
        offset += len(results)
        processed += len(results)
        if processed % 100_000 < len(results):
            total_text = total if total is not None else "?"
            print(
                f"Compared {processed}/{total_text} Meilisearch documents", flush=True
            )
    return processed


def load_candidate_metadata(kvrocks, connection, batch_size=1000):
    """Load Kvrocks timestamp/IP metadata for remaining candidates."""
    candidate_uids = [
        row[0] for row in connection.execute("SELECT uid FROM candidates")
    ]
    missing_by_ip = {}
    for uid_batch in chunked(candidate_uids, batch_size):
        pipe = kvrocks.pipeline(transaction=False)
        for uid in uid_batch:
            pipe.hgetall(f"doc:{uid}")
        metadata_batch = pipe.execute()
        updates = []
        for uid, metadata in zip(uid_batch, metadata_batch):
            ip = str((metadata or {}).get("ip") or "")
            first_seen = (metadata or {}).get("first_seen")
            last_seen = (metadata or {}).get("last_seen")
            updates.append((ip, first_seen, last_seen, uid))
            if ip:
                missing_by_ip.setdefault(ip, set()).add(uid)
        connection.executemany(
            "UPDATE candidates SET ip = ?, first_seen = ?, last_seen = ? WHERE uid = ?",
            updates,
        )
        connection.commit()
    return missing_by_ip


def iter_json_files(json_folder):
    """Yield raw job JSON paths without materializing the full file list."""
    for root, _directories, filenames in os.walk(json_folder):
        for filename in filenames:
            if filename.endswith(".json"):
                yield Path(root) / filename


def iter_scan_results(json_path):
    """Yield dict scan results from one raw job JSON file."""
    with open(json_path, "r", encoding="utf-8") as json_handle:
        payload = json.load(json_handle)
    if isinstance(payload, dict):
        yield payload
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item


def split_raw_scan_result(scan_result):
    """Build current port-scoped Meilisearch documents from one raw scan result."""
    ip = str(scan_result.get("addr") or "")
    ports = scan_result.get("ports") or []
    if not ip or not isinstance(ports, list):
        return []

    documents = []
    for port in ports:
        if not isinstance(port, dict):
            continue
        hashed_port = add_port_hash(port)
        if not str(hashed_port.get("portid") or "").strip():
            continue
        if not str(hashed_port.get("hsh256") or "").strip():
            continue
        document_id = port_document_uuid(ip, hashed_port)
        body = copy.deepcopy(scan_result)
        body["ports"] = [strip_port_hash(hashed_port)]
        body["hsh256"] = hashed_port["hsh256"]
        documents.append({"id": document_id, "ip": ip, "body": body})
    return documents


def normalized_observation_time(document, file_mtime):
    """Return sortable observation time, falling back to source file mtime."""
    body = document.get("body") or {}
    for field in ("endtime", "starttime"):
        value = body.get(field)
        if value in (None, ""):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return parsed.timestamp()
            except ValueError:
                continue
    return file_mtime


def store_newest_candidate(connection, document, json_path, file_mtime):
    """Persist a recovered document when it is newer than current source."""
    uid = document["id"]
    source_seen = normalized_observation_time(document, file_mtime)
    current = connection.execute(
        "SELECT source_seen, source_mtime FROM candidates WHERE uid = ?",
        (uid,),
    ).fetchone()
    if current and current[0] is not None:
        current_key = (float(current[0]), float(current[1] or 0))
        if current_key >= (source_seen, file_mtime):
            return uid

    connection.execute(
        """
        UPDATE candidates
        SET source_path = ?, source_seen = ?, source_mtime = ?, document_json = ?
        WHERE uid = ?
        """,
        (
            str(json_path),
            source_seen,
            file_mtime,
            json.dumps(document, separators=(",", ":")),
            uid,
        ),
    )
    return uid


def recover_candidates_from_file(json_path, missing_by_ip, connection):
    """Recover matching candidates from one raw job JSON file."""
    file_mtime = json_path.stat().st_mtime
    recovered_uids = set()
    matched_occurrences = 0
    for scan_result in iter_scan_results(json_path):
        wanted_uids = missing_by_ip.get(str(scan_result.get("addr") or ""))
        if not wanted_uids:
            continue
        for document in split_raw_scan_result(scan_result):
            if document["id"] not in wanted_uids:
                continue
            matched_occurrences += 1
            recovered_uids.add(
                store_newest_candidate(
                    connection,
                    document,
                    json_path,
                    file_mtime,
                )
            )
    return recovered_uids, matched_occurrences


def recover_candidates_from_json(
    json_folder,
    missing_by_ip,
    connection,
    progress_every=10_000,
):
    """Find newest raw source document for each missing UID."""
    files_processed = 0
    read_errors = 0
    matched_occurrences = 0
    recovered_uids = set()

    for json_path in iter_json_files(json_folder):
        files_processed += 1
        try:
            file_uids, file_occurrences = recover_candidates_from_file(
                json_path,
                missing_by_ip,
                connection,
            )
            recovered_uids.update(file_uids)
            matched_occurrences += file_occurrences
            if files_processed % 1000 == 0:
                connection.commit()
        except (OSError, TypeError, ValueError) as error:
            read_errors += 1
            print(f"[WARN] Unable to read {json_path}: {error}", flush=True)

        if progress_every > 0 and files_processed % progress_every == 0:
            print(
                f"Scanned {files_processed} raw JSON files; "
                f"recovered={len(recovered_uids)}; errors={read_errors}",
                flush=True,
            )

    connection.commit()
    return {
        "files_processed": files_processed,
        "read_errors": read_errors,
        "matched_occurrences": matched_occurrences,
        "recovered": len(recovered_uids),
    }


def get_task_uid(queued_task):
    """Extract a task UID from Meilisearch SDK response variants."""
    task_uid = getattr(queued_task, "task_uid", None)
    if task_uid is None:
        task_uid = getattr(queued_task, "uid", None)
    if task_uid is None:
        raise ReintegrationError("Meilisearch returned no task identifier")
    return int(task_uid)


def wait_for_task_uid(index, task_uid, timeout_ms):
    """Poll one Meilisearch task, print progress, and require success."""
    started_at = time.monotonic()
    next_status_at = 0
    while True:
        completed_task = index.get_task(task_uid)
        status = str(getattr(completed_task, "status", "")).lower()
        elapsed_seconds = time.monotonic() - started_at
        if status == "succeeded":
            print(
                f"Meilisearch task {task_uid}: succeeded after "
                f"{elapsed_seconds:.1f}s",
                flush=True,
            )
            return task_uid
        if status not in ("enqueued", "processing"):
            raise MeiliTaskFailed(
                task_uid,
                status,
                getattr(completed_task, "error", None),
            )
        if elapsed_seconds >= next_status_at:
            print(
                f"Meilisearch task {task_uid}: status={status}; "
                f"elapsed={elapsed_seconds:.1f}s; "
                f"timeout={timeout_ms / 1000:.1f}s",
                flush=True,
            )
            next_status_at = elapsed_seconds + TASK_STATUS_INTERVAL_SECONDS
        if elapsed_seconds >= timeout_ms / 1000:
            raise ReintegrationError(
                f"Meilisearch task {task_uid} still {status} after "
                f"{elapsed_seconds:.1f}s; work DB preserved for --resume-work-db"
            )
        time.sleep(TASK_POLL_INTERVAL_SECONDS)


def wait_for_success(index, queued_task, timeout_ms):
    """Wait for one queued Meilisearch task and require success."""
    return wait_for_task_uid(index, get_task_uid(queued_task), timeout_ms)


def reconcile_submitted_tasks(index, connection, timeout_ms):
    """Finish tasks submitted before interruption without duplicate insertion."""
    task_uids = [
        row[0]
        for row in connection.execute(
            "SELECT DISTINCT task_uid FROM candidates "
            "WHERE task_uid IS NOT NULL AND reintegrated = 0 ORDER BY task_uid"
        )
    ]
    confirmed = 0
    for task_uid in task_uids:
        affected = connection.execute(
            "SELECT COUNT(*) FROM candidates "
            "WHERE task_uid = ? AND reintegrated = 0",
            (task_uid,),
        ).fetchone()[0]
        print(
            f"Resuming Meilisearch task {task_uid}: documents={affected}",
            flush=True,
        )
        try:
            wait_for_task_uid(index, task_uid, timeout_ms)
        except MeiliTaskFailed:
            connection.execute(
                "UPDATE candidates SET task_uid = NULL WHERE task_uid = ?",
                (task_uid,),
            )
            connection.commit()
            raise
        connection.execute(
            "UPDATE candidates SET reintegrated = 1, task_uid = NULL "
            "WHERE task_uid = ?",
            (task_uid,),
        )
        connection.commit()
        confirmed += affected
    return confirmed


def reinsert_recovered_documents(index, connection, batch_size, timeout_ms):
    """Insert recovered documents in confirmed Meilisearch batches."""
    recovered_total = connection.execute(
        "SELECT COUNT(*) FROM candidates WHERE document_json IS NOT NULL"
    ).fetchone()[0]
    already_confirmed = connection.execute(
        "SELECT COUNT(*) FROM candidates WHERE reintegrated = 1"
    ).fetchone()[0]
    resumed_confirmed = reconcile_submitted_tasks(index, connection, timeout_ms)
    confirmed = already_confirmed + resumed_confirmed
    pending_total = recovered_total - confirmed
    batch_total = (pending_total + batch_size - 1) // batch_size
    batch_number = 0

    while True:
        row_batch = connection.execute(
            "SELECT uid, document_json FROM candidates "
            "WHERE document_json IS NOT NULL AND reintegrated = 0 "
            "AND task_uid IS NULL ORDER BY uid LIMIT ?",
            (batch_size,),
        ).fetchall()
        if not row_batch:
            break
        batch_number += 1
        documents = [json.loads(row[1]) for row in row_batch]
        print(
            f"Submitting Meilisearch batch {batch_number}/{batch_total}: "
            f"documents={len(documents)}; "
            f"confirmed={confirmed}/{recovered_total}",
            flush=True,
        )
        queued_task = index.add_documents(documents)
        task_uid = get_task_uid(queued_task)
        connection.executemany(
            "UPDATE candidates SET task_uid = ? WHERE uid = ?",
            ((task_uid, row[0]) for row in row_batch),
        )
        connection.commit()
        print(
            f"Meilisearch batch {batch_number}/{batch_total}: task_uid={task_uid}",
            flush=True,
        )
        try:
            wait_for_task_uid(index, task_uid, timeout_ms)
        except MeiliTaskFailed:
            connection.execute(
                "UPDATE candidates SET task_uid = NULL WHERE task_uid = ?",
                (task_uid,),
            )
            connection.commit()
            raise
        connection.execute(
            "UPDATE candidates SET reintegrated = 1, task_uid = NULL "
            "WHERE task_uid = ?",
            (task_uid,),
        )
        connection.commit()
        confirmed += len(documents)
        print(
            f"Reintegration progress: confirmed={confirmed}/{recovered_total}",
            flush=True,
        )
    return confirmed - already_confirmed


def write_report(report_path, connection):
    """Write one row per missing UID and return status counts."""
    report_path = Path(report_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    counts = {"reintegrated": 0, "recoverable": 0, "unrecoverable": 0}
    with open(report_path, "w", encoding="utf-8", newline="") as report_handle:
        writer = csv.writer(report_handle)
        writer.writerow(
            [
                "uid",
                "status",
                "ip",
                "first_seen",
                "last_seen",
                "source_seen",
                "source_path",
            ]
        )
        rows = connection.execute("""
            SELECT uid,
                   CASE
                       WHEN reintegrated = 1 THEN 'reintegrated'
                       WHEN document_json IS NULL THEN 'unrecoverable'
                       ELSE 'recoverable'
                   END AS status,
                   ip, first_seen, last_seen, source_seen, source_path
            FROM candidates ORDER BY uid
            """)
        for row in rows:
            counts[row[1]] += 1
            writer.writerow(row)
    return report_path, counts


def remove_work_database(connection, work_path):
    """Close and remove a temporary SQLite work DB plus sidecar files."""
    connection.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(f"{work_path}{suffix}").unlink()
        except FileNotFoundError:
            pass


def validate_args(args):
    """Reject unsafe or nonsensical operational settings."""
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be >= 1")
    if args.task_timeout_ms <= 0:
        raise SystemExit("--task-timeout-ms must be >= 1")
    if args.progress_every < 0:
        raise SystemExit("--progress-every must be >= 0")
    if args.resume_work_db and not args.apply:
        raise SystemExit("--resume-work-db requires --apply")


def build_backend_clients(config, index_name):
    """Build and validate runtime Kvrocks and Meilisearch clients."""
    import meilisearch  # pylint: disable=import-outside-toplevel
    import redis  # pylint: disable=import-outside-toplevel

    kvrocks = redis.Redis(
        host=config.KVROCKS_HOST,
        port=int(config.KVROCKS_PORT),
        decode_responses=True,
        db=0,
    )
    meili = meilisearch.Client(config.MEILI_DATABASE_URI, config.MEILI_KEY)
    index = meili.index(index_name)
    kvrocks.ping()
    index.get_stats()
    return kvrocks, index


def run_reintegration(args, json_folder, kvrocks, index, connection):
    """Run consistency comparison, raw recovery, and optional reinsertion."""
    kvrocks_count = snapshot_kvrocks_uids(kvrocks, connection)
    meili_count = remove_present_meili_uids(index, connection, args.batch_size)
    missing_count = connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
    print(
        f"Index comparison: Kvrocks={kvrocks_count}; "
        f"Meilisearch={meili_count}; missing={missing_count}",
        flush=True,
    )

    if not missing_count:
        report_path, _counts = write_report(args.report, connection)
        print(f"Report: {report_path}", flush=True)
        print(
            "Summary: reintegrated=0; recoverable=0; unrecoverable=0; inserted=0",
            flush=True,
        )
        return 0

    missing_by_ip = load_candidate_metadata(kvrocks, connection)
    recovery = recover_candidates_from_json(
        json_folder,
        missing_by_ip,
        connection,
        progress_every=args.progress_every,
    )
    print(
        "Raw recovery: "
        f"files={recovery['files_processed']}; "
        f"matched_occurrences={recovery['matched_occurrences']}; "
        f"recovered={recovery['recovered']}; "
        f"read_errors={recovery['read_errors']}",
        flush=True,
    )

    inserted = 0
    if args.apply:
        inserted = reinsert_recovered_documents(
            index,
            connection,
            args.batch_size,
            args.task_timeout_ms,
        )

    report_path, counts = write_report(args.report, connection)
    print(f"Report: {report_path}", flush=True)
    print(
        "Summary: "
        f"reintegrated={counts['reintegrated']}; "
        f"recoverable={counts['recoverable']}; "
        f"unrecoverable={counts['unrecoverable']}; "
        f"inserted={inserted}",
        flush=True,
    )
    if counts["unrecoverable"]:
        return 2
    return 0


def resume_reintegration(args, index, connection):
    """Resume confirmed-batch insertion without repeating index/raw scans."""
    candidate_count = connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[
        0
    ]
    recovered_count = connection.execute(
        "SELECT COUNT(*) FROM candidates WHERE document_json IS NOT NULL"
    ).fetchone()[0]
    confirmed_count = connection.execute(
        "SELECT COUNT(*) FROM candidates WHERE reintegrated = 1"
    ).fetchone()[0]
    print(
        f"Resume state: candidates={candidate_count}; recovered={recovered_count}; "
        f"already_confirmed={confirmed_count}",
        flush=True,
    )
    inserted = reinsert_recovered_documents(
        index,
        connection,
        args.batch_size,
        args.task_timeout_ms,
    )
    report_path, counts = write_report(args.report, connection)
    print(f"Report: {report_path}", flush=True)
    print(
        "Summary: "
        f"reintegrated={counts['reintegrated']}; "
        f"recoverable={counts['recoverable']}; "
        f"unrecoverable={counts['unrecoverable']}; "
        f"confirmed_this_run={inserted}",
        flush=True,
    )
    return 2 if counts["unrecoverable"] else 0


def main():
    """Configure and run missing-document reintegration."""
    args = parse_args()
    validate_args(args)

    config = load_runtime_config(args.config)
    json_folder = Path(args.json_folder or config.JSON_FOLDER).resolve()
    if not args.resume_work_db and not json_folder.is_dir():
        raise SystemExit(f"JSON folder not found: {json_folder}")

    mode = (
        "RESUME APPLY"
        if args.resume_work_db
        else ("APPLY" if args.apply else "DRY-RUN")
    )
    print(f"Mode: {mode}", flush=True)
    if not args.resume_work_db:
        print(f"Raw JSON folder: {json_folder}", flush=True)
    print(
        f"Meilisearch: {config.MEILI_DATABASE_URI} / index={args.index_name}",
        flush=True,
    )
    print(f"Kvrocks: {config.KVROCKS_HOST}:{config.KVROCKS_PORT}", flush=True)

    kvrocks, index = build_backend_clients(config, args.index_name)

    if args.resume_work_db:
        connection, work_path = open_work_database(args.resume_work_db)
        temporary_work_db = False
    else:
        connection, work_path, temporary_work_db = create_work_database(args.work_db)
    print(f"Work DB: {work_path}", flush=True)
    completed = False
    try:
        if args.resume_work_db:
            result = resume_reintegration(args, index, connection)
        else:
            result = run_reintegration(args, json_folder, kvrocks, index, connection)
        completed = True
        return result
    finally:
        if temporary_work_db and completed:
            remove_work_database(connection, work_path)
        else:
            connection.close()
            if temporary_work_db:
                print(
                    f"Work DB preserved after interruption/error: {work_path}",
                    flush=True,
                )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReintegrationError as error:
        print(f"[ERROR] {error}", flush=True)
        raise SystemExit(1) from error
