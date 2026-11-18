#!/bin/env python
"""
Import dumped Meilisearch JSON documents into the configured OUT Meilisearch.
"""

import argparse
import hashlib
import json
import os
import tempfile
import time
from itertools import islice
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "meili_dump"
DEFAULT_BATCH_SIZE = 5000
DEFAULT_TASK_TIMEOUT_MS = 0
TASK_STATUS_INTERVAL_MS = 30_000
COUNTERS = ("processed", "indexed", "errors")


def load_config():
    """
    Load tools/config.yaml.
    """
    import yaml  # pylint: disable=import-outside-toplevel

    with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def get_config_value(config, *names, default=None):
    """
    Return the first configured value for a list of key names.
    """
    for name in names:
        value = config.get(name)
        if value not in (None, ""):
            return value
    return default


def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Import dumped JSON documents into OUT Meilisearch."
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help=f"Directory containing dumped JSON documents. Default: {DEFAULT_INPUT_DIR}",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Documents per Meilisearch batch. Default: {DEFAULT_BATCH_SIZE}",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Count total documents before importing and show percentages. "
            "This makes startup slower on large dumps."
        ),
    )
    parser.add_argument(
        "--task-timeout-ms",
        type=int,
        default=DEFAULT_TASK_TIMEOUT_MS,
        help=(
            "Maximum task wait in milliseconds; 0 waits until completion. "
            "Default: 0 (unlimited). A timeout retains the task for --continue."
        ),
    )
    parser.add_argument(
        "--continue",
        dest="resume",
        action="store_true",
        help="Resume any saved task, then import after the last confirmed batch.",
    )
    parser.add_argument(
        "--checkpoint",
        help="Checkpoint path. Default: <input-dir>/.index-meili-checkpoint",
    )
    parser.add_argument(
        "--stat",
        action="store_true",
        help=(
            "Show current OUT Meilisearch indexing state and pending document "
            "work, then exit."
        ),
    )
    return parser.parse_args()


def iter_json_files(input_dir):
    """
    Iterate every dumped Meilisearch JSON document.
    """
    for json_file in sorted(input_dir.rglob("*.json")):
        if json_file.is_file():
            yield json_file


def iter_documents(json_files):
    """
    Yield documents from JSON files.
    """
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as json_handle:
                obj = json.load(json_handle)
        except Exception as error:  # pylint: disable=broad-except
            yield None, f"[WARN] Unable to read {json_file}: {error}"
            continue

        if isinstance(obj, dict):
            yield obj, None
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item, None
                else:
                    yield None, f"[WARN] Unsupported item type in {json_file}: {type(item)}"
        else:
            yield None, f"[WARN] Unsupported JSON type in {json_file}: {type(obj)}"


def count_documents(json_files):
    """
    Count importable documents and unreadable/unsupported JSON entries.
    """
    total_count = 0
    error_count = 0
    for doc, error in iter_documents(json_files):
        if error:
            error_count += 1
            continue
        if doc is not None:
            total_count += 1
    return total_count, error_count


def import_identity(json_files, input_dir, meili_url, index_name):
    """Bind a checkpoint to the destination and ordered dump file metadata."""
    digest = hashlib.sha3_512()
    for json_file in json_files:
        stat = json_file.stat()
        values = [str(json_file.relative_to(input_dir)), stat.st_size, stat.st_mtime_ns]
        digest.update((json.dumps(values, ensure_ascii=True) + "|").encode("utf-8"))
    return {
        "version": 1,
        "input_dir": str(input_dir),
        "url": meili_url,
        "index": index_name,
        "manifest": digest.hexdigest(),
    }


def load_checkpoint(path, identity):
    """Validate a saved import position before skipping any source entries."""
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"Cannot read checkpoint {path}: {error}") from error
    if not isinstance(state, dict) or state.get("identity") != identity:
        raise SystemExit(
            "Checkpoint dump or destination differs; restart without --continue"
        )
    counts = [state.get(key) for key in COUNTERS]
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts
    ):
        raise SystemExit("Invalid checkpoint counters")
    if counts[0] != counts[1] + counts[2]:
        raise SystemExit("Inconsistent checkpoint counters")
    pending = state.get("pending")
    if pending is not None:
        if not isinstance(pending, dict):
            raise SystemExit("Invalid pending import task")
        future = [pending.get(key) for key in COUNTERS]
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < before
            for value, before in zip(future, counts)
        ):
            raise SystemExit("Invalid pending import counters")
        if future[0] != future[1] + future[2] or future[1] <= counts[1]:
            raise SystemExit("Inconsistent pending import counters")
        uid = pending.get("task_uid")
        if uid is not None and (
            not isinstance(uid, int) or isinstance(uid, bool) or uid < 0
        ):
            raise SystemExit("Invalid pending Meilisearch task UID")
    return state


def save_checkpoint(  # pylint: disable=too-many-arguments
    path, identity, processed, indexed, errors, *, pending=None
):
    """Persist confirmed counters separately from an unconfirmed task's position."""
    state = {
        "identity": identity,
        "processed": processed,
        "indexed": indexed,
        "errors": errors,
    }
    if pending is not None:
        state["pending"] = pending
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def checkpoint_state(path, identity, resume):
    """Load confirmed work or initialize an import without discarding pending work."""
    if resume:
        return load_checkpoint(path, identity)
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise SystemExit(f"Cannot read checkpoint {path}: {error}") from error
        if isinstance(previous, dict) and previous.get("pending") is not None:
            raise SystemExit("Checkpoint has a pending task; use --continue")
    save_checkpoint(path, identity, 0, 0, 0)
    return {key: 0 for key in COUNTERS}


def format_progress(count, total_count):
    """
    Format count with percentage.
    """
    if total_count:
        percentage = (count / total_count) * 100
        return f"{count}/{total_count} ({percentage:.1f}%)"
    return str(count)


def wait_for_import_task(index, uid, task_timeout_ms):
    """Poll one accepted task; a local wait timeout never submits another batch."""
    from meilisearch.errors import (  # pylint: disable=import-outside-toplevel
        MeilisearchTimeoutError,
    )

    started = time.monotonic()
    print(f"Waiting for Meilisearch task {uid}...", flush=True)
    while True:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if task_timeout_ms and elapsed_ms >= task_timeout_ms:
            raise SystemExit(
                f"Wait limit reached for task {uid}; checkpoint retains its UID. "
                "Meilisearch may still be processing it. Resume with --continue."
            )
        wait_ms = TASK_STATUS_INTERVAL_MS
        if task_timeout_ms:
            wait_ms = min(wait_ms, task_timeout_ms - elapsed_ms)
        try:
            return index.wait_for_task(uid, timeout_in_ms=wait_ms, interval_in_ms=1000)
        except MeilisearchTimeoutError:
            elapsed = int(time.monotonic() - started)
            print(
                f"Task {uid}: still waiting after {elapsed}s; keeping the same task.",
                flush=True,
            )


class ImportCheckpoint:
    """Journal submission intent and task UID before advancing confirmed progress."""

    def __init__(self, path, identity, state, task_timeout_ms=DEFAULT_TASK_TIMEOUT_MS):
        self.path = path
        self.identity = identity
        self.state = state
        self.task_timeout_ms = task_timeout_ms

    def save(self, **changes):
        """Publish in-memory state only after the atomic checkpoint write succeeds."""
        state = dict(self.state, **changes)
        save_checkpoint(
            self.path,
            self.identity,
            *(state[key] for key in COUNTERS),
            pending=state.get("pending"),
        )
        self.state = state

    def finish_pending(self, index):
        """Confirm a retained task without resubmission, including after a restart."""
        pending = self.state.get("pending")
        if pending is None:
            return
        uid = pending.get("task_uid")
        if uid is None:
            raise SystemExit(
                "Submission was interrupted before its task UID was saved. "
                "Check Meilisearch tasks before restarting; no batch was resubmitted."
            )
        task = wait_for_import_task(index, uid, self.task_timeout_ms)
        if task.status != "succeeded":
            error = (task.error or {}).get("message", "no error details")
            if task.status in ("failed", "canceled"):
                # Only a confirmed terminal failure permits submission on retry.
                self.save(pending=None)
            raise RuntimeError(
                f"Meilisearch task {uid} ended with status {task.status}: {error}. "
                "Confirmed counters unchanged; use --continue to retry."
            )
        expected = pending["indexed"] - self.state["indexed"]
        if (
            task.uid != uid
            or task.index_uid != self.identity["index"]
            or task.type != "documentAdditionOrUpdate"
            or (task.details or {}).get("receivedDocuments") != expected
        ):
            raise RuntimeError(
                f"Task {uid} does not match the pending import batch; "
                "checkpoint unchanged."
            )
        self.save(**{key: pending[key] for key in COUNTERS}, pending=None)

    def flush(self, index, batch, processed, errors):
        """Record intent before POST, then task UID before waiting for completion."""
        if not batch:
            return
        if self.state.get("pending") is not None:
            raise RuntimeError("Resolve the pending import task before submitting")
        pending = {
            "task_uid": None,
            "processed": processed,
            "indexed": self.state["indexed"] + len(batch),
            "errors": errors,
        }
        self.save(pending=pending)
        task_info = index.add_documents(batch)
        self.save(pending=dict(pending, task_uid=task_info.task_uid))
        self.finish_pending(index)
        batch.clear()


def active_indexing_tasks(client, index_name):
    """Return every queued or processing task for one index."""
    tasks = []
    task_from = None
    while True:
        parameters = {
            "indexUids": index_name,
            "statuses": "enqueued,processing",
            "limit": 1000,
        }
        if task_from is not None:
            parameters["from"] = task_from
        page = client.get_tasks(parameters)
        tasks.extend(page.results)
        if page.next_ is None:
            return tasks
        task_from = page.next_


def print_indexing_status(client, index, index_name):
    """Print Meilisearch document count and outstanding indexing work."""
    stats = index.get_stats()
    tasks = active_indexing_tasks(client, index_name)
    queued = sum(task.status == "enqueued" for task in tasks)
    processing = sum(task.status == "processing" for task in tasks)
    received = sum((task.details or {}).get("receivedDocuments", 0) for task in tasks)
    indexed = sum((task.details or {}).get("indexedDocuments", 0) for task in tasks)
    remaining = max(0, received - indexed)

    print(
        "Meilisearch status: "
        f"documents={stats.number_of_documents}; "
        f"is_indexing={stats.is_indexing}; "
        f"tasks_queued={queued}; tasks_processing={processing}; "
        f"submitted_documents={received}; "
        f"task_indexed_documents={indexed}; "
        f"pending_documents={remaining}",
        flush=True,
    )


def main():  # pylint: disable=too-many-locals,too-many-statements
    """
    Import dump documents into OUT Meilisearch.
    """
    args = parse_args()
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be >= 1")
    if args.task_timeout_ms < 0:
        raise SystemExit("--task-timeout-ms must be >= 0")

    import meilisearch  # pylint: disable=import-outside-toplevel

    config = load_config()
    meili_url = get_config_value(config, "OUT_MEILI_URL")
    meili_api_key = get_config_value(config, "OUT_MEILI_API_KEY")
    index_name = get_config_value(config, "INDEX_NAME", default="plum")

    if not meili_url:
        raise SystemExit("Missing OUT_MEILI_URL in tools/config.yaml")

    client = meilisearch.Client(meili_url, meili_api_key, timeout=30)
    index = client.index(index_name)

    if args.stat:
        print(f"Meilisearch: {meili_url} / index={index_name}", flush=True)
        print_indexing_status(client, index, index_name)
        return

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory not found: {input_dir}")

    checkpoint = (
        Path(args.checkpoint).resolve()
        if args.checkpoint
        else input_dir / ".index-meili-checkpoint"
    )
    if checkpoint.suffix.lower() == ".json":
        raise SystemExit("Checkpoint must not use .json (reserved for dump documents)")
    print(
        f"Discovering and sorting JSON files in {input_dir}... "
        "Large dumps may take a while; please wait.",
        flush=True,
    )
    json_files = list(iter_json_files(input_dir))
    print(
        f"Checking metadata for {len(json_files)} JSON files "
        "to validate the import checkpoint...",
        flush=True,
    )
    identity = import_identity(json_files, input_dir, meili_url, index_name)
    state = checkpoint_state(checkpoint, identity, args.resume)
    journal = ImportCheckpoint(checkpoint, identity, state, args.task_timeout_ms)
    journal.finish_pending(index)
    processed_count, indexed_count, error_count = (
        journal.state[key] for key in COUNTERS
    )
    if args.resume:
        print(
            f"Resuming: processed={processed_count}; indexed={indexed_count}; errors={error_count}",
            flush=True,
        )

    print(f"Reading JSON dump from {input_dir}", flush=True)
    print(f"Writing documents to {meili_url} / index={index_name}", flush=True)
    print(f"Batch size: {args.batch_size}", flush=True)
    timeout = f"{args.task_timeout_ms} ms" if args.task_timeout_ms else "unlimited"
    print(f"Task timeout: {timeout}", flush=True)
    total_count = None
    if args.progress:
        print("Counting JSON documents...", flush=True)
        total_count, preflight_error_count = count_documents(json_files)
        print(
            f"Found {total_count} importable documents "
            f"({preflight_error_count} preflight errors)",
            flush=True,
        )

    batch = []

    # Replay the prefix locally to support checkpoints inside multi-document files.
    # Only entries following the confirmed position are submitted to Meilisearch.
    print(
        "Preparing import: "
        f"skipping {processed_count} previously processed entries locally... "
        "Large resumed imports may take a while; please wait.",
        flush=True,
    )
    documents = islice(iter_documents(json_files), processed_count, None)
    for doc, error in documents:
        processed_count += 1
        if error:
            error_count += 1
            print(error, flush=True)
            continue

        batch.append(doc)
        if len(batch) >= args.batch_size:
            journal.flush(index, batch, processed_count, error_count)
            indexed_count = journal.state["indexed"]
            print(
                f"Progress: processed={processed_count}; "
                f"indexed={format_progress(indexed_count, total_count)}; "
                f"errors={error_count}",
                flush=True,
            )

    journal.flush(index, batch, processed_count, error_count)
    indexed_count = journal.state["indexed"]
    journal.save(processed=processed_count, errors=error_count)
    print(
        "Meilisearch import complete; every submitted batch succeeded: "
        f"processed={processed_count} "
        f"indexed={format_progress(indexed_count, total_count)} "
        f"errors={error_count}",
        flush=True,
    )
    print_indexing_status(client, index, index_name)


if __name__ == "__main__":
    main()
