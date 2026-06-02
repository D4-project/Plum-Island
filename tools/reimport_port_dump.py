#!/usr/bin/env python3
"""
Fully re-import a port-scoped Meilisearch dump.

Default workflow:
- read JSON documents from tools/meili_dump_port,
- replace all documents in OUT Meilisearch,
- rebuild OUT Kvrocks indexes with active tag rules,
- apply first_seen/last_seen from companion .time files.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import index_kvrocks

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "meili_dump_port"
DEFAULT_BATCH_SIZE = 1000
DEFAULT_MEILI_TIMEOUT_MS = 60 * 60 * 1000
DEFAULT_MEILI_INTERVAL_MS = 1000
DEFAULT_MEILI_QUEUE_DEPTH = 8
DEFAULT_MEILI_REPLACE_MODE = "swap"


def parse_args(argv=None):
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Replace OUT Meilisearch and rebuild OUT Kvrocks from a port-scoped "
            "dump directory, preserving timestamps from .time companion files."
        )
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help=f"Port-scoped dump directory. Default: {DEFAULT_INPUT_DIR}",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Documents per Meili/Kvrocks batch. Default: tools config or 1000.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=index_kvrocks.DEFAULT_WORKERS,
        help=(
            "Parser worker processes for Kvrocks rebuild. Use 1 to disable "
            f"multiprocessing. Default: {index_kvrocks.DEFAULT_WORKERS}."
        ),
    )
    parser.add_argument(
        "--meili-timeout-ms",
        type=int,
        default=DEFAULT_MEILI_TIMEOUT_MS,
        help=(
            "Timeout for each Meilisearch task wait. "
            f"Default: {DEFAULT_MEILI_TIMEOUT_MS}."
        ),
    )
    parser.add_argument(
        "--meili-interval-ms",
        type=int,
        default=DEFAULT_MEILI_INTERVAL_MS,
        help=(
            "Polling interval for Meilisearch task waits. "
            f"Default: {DEFAULT_MEILI_INTERVAL_MS}."
        ),
    )
    parser.add_argument(
        "--meili-queue-depth",
        type=int,
        default=DEFAULT_MEILI_QUEUE_DEPTH,
        help=(
            "Number of Meilisearch add-document tasks to enqueue before "
            f"waiting for the oldest one. Use 1 for serial mode. "
            f"Default: {DEFAULT_MEILI_QUEUE_DEPTH}."
        ),
    )
    parser.add_argument(
        "--meili-replace-mode",
        choices=("swap", "delete-all"),
        default=DEFAULT_MEILI_REPLACE_MODE,
        help=(
            "How to replace Meilisearch data. swap imports into a temporary "
            "index then atomically swaps it with the target. delete-all keeps "
            f"the old behavior. Default: {DEFAULT_MEILI_REPLACE_MODE}."
        ),
    )
    parser.add_argument(
        "--skip-meili",
        action="store_true",
        help="Do not replace OUT Meilisearch; only rebuild OUT Kvrocks.",
    )
    parser.add_argument(
        "--skip-kvrocks",
        action="store_true",
        help="Do not rebuild OUT Kvrocks; only replace OUT Meilisearch.",
    )
    parser.add_argument(
        "--areyousure_yes",
        action="store_true",
        help=(
            "Required. Confirms destructive replacement of OUT Meilisearch "
            "documents and OUT Kvrocks indexes."
        ),
    )
    args = parser.parse_args(argv)
    if not args.areyousure_yes:
        parser.print_help(sys.stderr)
        parser.error(
            "--areyousure_yes is required because this replaces OUT Meilisearch "
            "documents and rebuilds OUT Kvrocks"
        )
    if args.skip_meili and args.skip_kvrocks:
        parser.error("--skip-meili and --skip-kvrocks together would do nothing")
    if args.meili_timeout_ms <= 0:
        parser.error("--meili-timeout-ms must be >= 1")
    if args.meili_interval_ms <= 0:
        parser.error("--meili-interval-ms must be >= 1")
    if args.meili_queue_depth <= 0:
        parser.error("--meili-queue-depth must be >= 1")
    return args


def iter_json_files(input_dir):
    """
    Iterate port-scoped JSON documents.
    """
    for json_file in sorted(input_dir.rglob("*.json")):
        if json_file.is_file():
            yield json_file


def iter_documents(json_files):
    """
    Yield Meilisearch documents from JSON files.
    """
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as json_handle:
                obj = json.load(json_handle)
        except Exception as error:  # pylint: disable=broad-except
            yield None, f"[WARN] Unable to read {json_file}: {error}"
            continue

        if isinstance(obj, dict):
            yield strip_port_hashes_from_document(obj), None
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield strip_port_hashes_from_document(item), None
                else:
                    yield None, (
                        f"[WARN] Unsupported item type in {json_file}: {type(item)}"
                    )
        else:
            yield None, f"[WARN] Unsupported JSON type in {json_file}: {type(obj)}"


def strip_port_hashes_from_document(doc):
    """
    Return a Meilisearch document copy without per-port hsh256 helper fields.
    """
    cleaned_doc = dict(doc)
    body = cleaned_doc.get("body")
    if not isinstance(body, dict):
        return cleaned_doc

    cleaned_body = dict(body)
    ports = cleaned_body.get("ports")
    if isinstance(ports, list):
        cleaned_ports = []
        for port in ports:
            if isinstance(port, dict):
                cleaned_port = dict(port)
                cleaned_port.pop("hsh256", None)
                cleaned_ports.append(cleaned_port)
            else:
                cleaned_ports.append(port)
        cleaned_body["ports"] = cleaned_ports
    cleaned_doc["body"] = cleaned_body
    return cleaned_doc


def task_uid(task_info):
    """
    Extract a Meilisearch task uid from py-meilisearch return types.
    """
    if task_info is None:
        return None
    for attribute in ("task_uid", "taskUid", "uid"):
        value = getattr(task_info, attribute, None)
        if value is not None:
            return value
    if isinstance(task_info, dict):
        for key in ("taskUid", "task_uid", "uid"):
            value = task_info.get(key)
            if value is not None:
                return value
    return None


def wait_for_task(client, task_info, label, timeout_ms, interval_ms):
    """
    Wait for one Meilisearch task when a task uid is available.
    """
    uid = task_uid(task_info)
    if uid is None:
        return
    print(
        f"Waiting Meili task {uid}: {label} "
        f"(timeout={timeout_ms}ms interval={interval_ms}ms)",
        flush=True,
    )
    try:
        task = client.wait_for_task(
            uid,
            timeout_in_ms=timeout_ms,
            interval_in_ms=interval_ms,
        )
    except Exception as error:  # pylint: disable=broad-except
        raise SystemExit(f"Meili task {uid} wait failed: {error}") from None
    status = getattr(task, "status", None)
    if status != "succeeded":
        error = getattr(task, "error", None)
        raise SystemExit(f"Meili task {uid} ended with status={status}: {error}")
    return task


def format_queue_depth(depth):
    """
    Format queued Meilisearch task count.
    """
    return f"queued_tasks={depth}"


def format_progress(count, total_count):
    """
    Format progress with percentage and todo count.
    """
    if not total_count:
        return str(count)
    percentage = (count / total_count) * 100
    todo = max(0, total_count - count)
    return f"{count}/{total_count} ({percentage:.1f}%) todo={todo}"


def load_time_snapshot(input_dir):
    """
    Load .time companion files into index_kvrocks seen_snapshot shape.
    """
    snapshot = {}
    missing = 0
    invalid = 0

    for json_file in iter_json_files(input_dir):
        time_file = json_file.with_suffix(".time")
        if not time_file.is_file():
            missing += 1
            continue

        try:
            with open(time_file, "r", encoding="utf-8") as time_handle:
                data = json.load(time_handle)
            first_seen, last_seen = index_kvrocks.KVrocksIndexer.normalize_seen_range(
                data.get("first_seen"), data.get("last_seen")
            )
        except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
            invalid += 1
            continue

        if first_seen is None or last_seen is None:
            invalid += 1
            continue
        snapshot[json_file.stem] = (first_seen, last_seen)

    print(
        "Loaded .time companions: "
        f"usable={len(snapshot)} missing={missing} invalid={invalid}",
        flush=True,
    )
    return snapshot


def build_out_meili_index():
    """
    Build OUT Meilisearch client and index from tools/config.yaml.
    """
    import meilisearch  # pylint: disable=import-outside-toplevel

    meili_url = index_kvrocks.get_config_value("OUT_MEILI_URL")
    meili_api_key = index_kvrocks.get_config_value("OUT_MEILI_API_KEY")
    index_name = index_kvrocks.get_config_value("INDEX_NAME", default="plum")

    if not meili_url:
        raise SystemExit("Missing OUT_MEILI_URL in tools/config.yaml")

    client = meilisearch.Client(meili_url, meili_api_key)
    return meili_url, index_name, client, client.index(index_name)


def validate_out_targets(skip_meili=False, skip_kvrocks=False):
    """
    Validate destructive targets from OUT config keys only.
    """
    errors = []
    if not skip_meili and not index_kvrocks.get_config_value("OUT_MEILI_URL"):
        errors.append("Missing OUT_MEILI_URL in tools/config.yaml")
    if not skip_kvrocks and not index_kvrocks.KVROCKS_HOST:
        errors.append("Missing OUT_KVROCKS_HOST in tools/config.yaml")
    if not skip_kvrocks and not index_kvrocks.KVROCKS_PORT:
        errors.append("Missing OUT_KVROCKS_PORT in tools/config.yaml")
    if errors:
        raise SystemExit("\n".join(errors))


def print_out_targets(skip_meili=False, skip_kvrocks=False):
    """
    Print configured destructive targets.
    """
    index_name = index_kvrocks.get_config_value("INDEX_NAME", default="plum")
    if not skip_meili:
        print(
            "OUT Meilisearch target: "
            f"url={index_kvrocks.get_config_value('OUT_MEILI_URL')} "
            f"index={index_name}",
            flush=True,
        )
    if not skip_kvrocks:
        print(
            "OUT Kvrocks target: "
            f"host={index_kvrocks.KVROCKS_HOST} "
            f"port={index_kvrocks.KVROCKS_PORT}",
            flush=True,
        )


def enqueue_meili_batch(index, batch, batch_number):
    """
    Send one batch to Meilisearch and return its task metadata.
    """
    if not batch:
        return None
    count = len(batch)
    task = index.add_documents(list(batch))
    batch.clear()
    return task, count, f"add batch {batch_number} ({count} documents)"


def wait_for_queued_meili_task(client, task_queue, timeout_ms, interval_ms):
    """
    Wait for the oldest queued Meilisearch task.
    """
    if not task_queue:
        return 0
    task_info, count, label = task_queue.pop(0)
    wait_for_task(client, task_info, label, timeout_ms, interval_ms)
    return count


def import_meili_documents_to_index(
    client,
    index,
    input_dir,
    batch_size,
    total_count,
    timeout_ms,
    interval_ms,
    queue_depth,
):
    """
    Import the port-scoped dump into one Meilisearch index.
    """
    batch = []
    task_queue = []
    batch_number = 0
    processed_count = 0
    queued_count = 0
    confirmed_count = 0
    error_count = 0
    started_at = time.monotonic()

    for doc, error in iter_documents(iter_json_files(input_dir)):
        processed_count += 1
        if error:
            error_count += 1
            print(error, flush=True)
            continue

        batch.append(doc)
        if len(batch) >= batch_size:
            batch_number += 1
            task_queue.append(enqueue_meili_batch(index, batch, batch_number))
            queued_count += task_queue[-1][1]
            print(
                "Meili progress: "
                f"processed={format_progress(processed_count, total_count)} "
                f"queued={format_progress(queued_count, total_count)} "
                f"confirmed={format_progress(confirmed_count, total_count)} "
                f"{format_queue_depth(len(task_queue))} errors={error_count}",
                flush=True,
            )

            if len(task_queue) >= queue_depth:
                confirmed_count += wait_for_queued_meili_task(
                    client,
                    task_queue,
                    timeout_ms,
                    interval_ms,
                )
                print(
                    "Meili progress: "
                    f"processed={format_progress(processed_count, total_count)} "
                    f"queued={format_progress(queued_count, total_count)} "
                    f"confirmed={format_progress(confirmed_count, total_count)} "
                    f"{format_queue_depth(len(task_queue))} errors={error_count}",
                    flush=True,
                )

    final_task = enqueue_meili_batch(index, batch, batch_number + 1)
    if final_task:
        batch_number += 1
        task_queue.append(final_task)
        queued_count += final_task[1]
        print(
            "Meili progress: "
            f"processed={format_progress(processed_count, total_count)} "
            f"queued={format_progress(queued_count, total_count)} "
            f"confirmed={format_progress(confirmed_count, total_count)} "
            f"{format_queue_depth(len(task_queue))} errors={error_count}",
            flush=True,
        )

    while task_queue:
        confirmed_count += wait_for_queued_meili_task(
            client,
            task_queue,
            timeout_ms,
            interval_ms,
        )
        print(
            "Meili progress: "
            f"processed={format_progress(processed_count, total_count)} "
            f"queued={format_progress(queued_count, total_count)} "
            f"confirmed={format_progress(confirmed_count, total_count)} "
            f"{format_queue_depth(len(task_queue))} errors={error_count}",
            flush=True,
        )

    elapsed = time.monotonic() - started_at
    print(
        "Meilisearch replace complete: "
        f"processed={processed_count} queued={queued_count} "
        f"confirmed={confirmed_count} errors={error_count} elapsed={elapsed:.1f}s",
        flush=True,
    )
    return processed_count, confirmed_count, error_count


def target_index_metadata(client, index_name, target_index, timeout_ms, interval_ms):
    """
    Return target primary key and settings, creating an empty target if missing.
    """
    primary_key = "id"
    try:
        primary_key = target_index.get_primary_key() or "id"
        settings = dict(target_index.get_settings() or {})
    except Exception as error:  # pylint: disable=broad-except
        if "index_not_found" not in str(error):
            raise SystemExit(f"Unable to read Meili target index {index_name}: {error}")
        print(
            f"Target Meilisearch index {index_name} missing; creating empty index",
            flush=True,
        )
        wait_for_task(
            client,
            client.create_index(index_name, {"primaryKey": primary_key}),
            f"create target index {index_name}",
            timeout_ms,
            interval_ms,
        )
        settings = {"filterableAttributes": ["ip"]}

    if not settings.get("filterableAttributes"):
        settings["filterableAttributes"] = ["ip"]
    return primary_key, settings


def create_import_index(
    client, index_name, primary_key, settings, timeout_ms, interval_ms
):
    """
    Create a temporary Meilisearch index and copy target settings into it.
    """
    import_index_name = f"{index_name}_import_{time.time_ns()}"
    print(
        f"Creating temporary Meilisearch index {import_index_name}",
        flush=True,
    )
    try:
        wait_for_task(
            client,
            client.create_index(import_index_name, {"primaryKey": primary_key}),
            f"create temporary index {import_index_name}",
            timeout_ms,
            interval_ms,
        )

        import_index = client.index(import_index_name)
        if settings:
            print(
                f"Copying settings to temporary Meilisearch index {import_index_name}",
                flush=True,
            )
            wait_for_task(
                client,
                import_index.update_settings(settings),
                f"copy settings to {import_index_name}",
                timeout_ms,
                interval_ms,
            )
    except (KeyboardInterrupt, SystemExit):
        cleanup_import_index(client, import_index_name, timeout_ms, interval_ms)
        raise
    return import_index_name, import_index


def cleanup_import_index(client, import_index_name, timeout_ms, interval_ms):
    """
    Best-effort cleanup for a temporary Meilisearch import index.
    """
    if not import_index_name:
        return
    print(
        f"Cleaning temporary Meilisearch index {import_index_name}",
        file=sys.stderr,
        flush=True,
    )
    try:
        wait_for_task(
            client,
            client.delete_index(import_index_name),
            f"delete temporary index {import_index_name}",
            timeout_ms,
            interval_ms,
        )
    except (Exception, SystemExit) as error:  # pylint: disable=broad-exception-caught
        print(
            f"[WARN] Unable to delete temporary Meilisearch index "
            f"{import_index_name}: {error}",
            file=sys.stderr,
            flush=True,
        )


def swap_import_index(client, index_name, import_index_name, timeout_ms, interval_ms):
    """
    Swap the fully imported temporary index into the target uid.
    """
    print(
        f"Swapping Meilisearch indexes: {index_name} <-> {import_index_name}",
        flush=True,
    )
    wait_for_task(
        client,
        client.swap_indexes([{"indexes": [index_name, import_index_name]}]),
        f"swap {index_name} and {import_index_name}",
        timeout_ms,
        interval_ms,
    )

    print(
        f"Deleting old Meilisearch content now held by {import_index_name}",
        flush=True,
    )
    wait_for_task(
        client,
        client.delete_index(import_index_name),
        f"delete old index {import_index_name}",
        timeout_ms,
        interval_ms,
    )


def replace_meili_from_dump(
    input_dir,
    batch_size,
    total_count,
    timeout_ms,
    interval_ms,
    queue_depth,
    replace_mode,
):
    """
    Replace OUT Meili docs and import the port-scoped dump.
    """
    meili_url, index_name, client, target_index = build_out_meili_index()
    print(
        "Replacing OUT Meilisearch documents at "
        f"{meili_url} / index={index_name} mode={replace_mode}",
        flush=True,
    )

    if replace_mode == "delete-all":
        wait_for_task(
            client,
            target_index.delete_all_documents(),
            "delete all documents",
            timeout_ms,
            interval_ms,
        )
        return import_meili_documents_to_index(
            client,
            target_index,
            input_dir,
            batch_size,
            total_count,
            timeout_ms,
            interval_ms,
            queue_depth,
        )

    primary_key, settings = target_index_metadata(
        client, index_name, target_index, timeout_ms, interval_ms
    )
    import_index_name = None
    swap_started = False
    try:
        import_index_name, import_index = create_import_index(
            client, index_name, primary_key, settings, timeout_ms, interval_ms
        )
        result = import_meili_documents_to_index(
            client,
            import_index,
            input_dir,
            batch_size,
            total_count,
            timeout_ms,
            interval_ms,
            queue_depth,
        )
        swap_started = True
        swap_import_index(
            client, index_name, import_index_name, timeout_ms, interval_ms
        )
    except (KeyboardInterrupt, SystemExit):
        if not swap_started:
            cleanup_import_index(client, import_index_name, timeout_ms, interval_ms)
        raise
    return result


def load_tool_config(batch_size):
    """
    Load tools/config.yaml and resolve the effective batch size.
    """
    index_kvrocks.suppress_connection_debug_logs()
    index_kvrocks.load_config()
    if batch_size is None:
        batch_size = index_kvrocks.BATCH_SIZE or DEFAULT_BATCH_SIZE
    return int(batch_size)


def prepare_index_kvrocks_runtime():
    """
    Load index_kvrocks config/runtime for parser, tags, and output Kvrocks.
    """
    index_kvrocks.load_runtime_dependencies(retag=True)
    index_kvrocks.suppress_connection_debug_logs()

    if index_kvrocks.PARSER_CONF["ONLINETLD"]:
        index_kvrocks.PARSER_CONF["TLDS"] = index_kvrocks.fetch_tlds()
    else:
        index_kvrocks.PARSER_CONF["TLDS"] = index_kvrocks.config.get(
            "TLDS", index_kvrocks.config.get("PARSER_TLDS", [])
        )
    index_kvrocks.PARSER_CONF["HTTP_HEADER_COLLECTION"] = (
        index_kvrocks.load_collected_header_collection()
    )


def rebuild_kvrocks_from_dump(input_dir, batch_size, workers, total_count):
    """
    Rebuild OUT Kvrocks from port-scoped dump and .time companions.
    """
    tag_rules, active_rule_count = index_kvrocks.load_active_tag_rules()
    print(
        f"Loaded {len(tag_rules)} compiled tag rules from "
        f"{active_rule_count} active DB rows",
        flush=True,
    )

    indexer = index_kvrocks.KVrocksIndexer(
        index_kvrocks.KVROCKS_HOST,
        index_kvrocks.KVROCKS_PORT,
    )
    seen_snapshot = load_time_snapshot(input_dir)

    index_kvrocks.rebuild_kvrocks(indexer, include_tags=True)
    deleted_doc_keys = index_kvrocks.delete_keys_by_pattern(indexer.r, "doc:*")
    if deleted_doc_keys:
        print(f"Deleted {deleted_doc_keys} keys matching doc:*", flush=True)

    source_docs = index_kvrocks.parsed_documents_from_files(
        input_dir,
        seen_snapshot,
        tag_rules=tag_rules,
        workers=workers,
        batch_size=batch_size,
    )

    index_kvrocks.install_graceful_interrupt_handler()
    processed_count, indexed_count, error_count = (
        index_kvrocks.index_documents_with_errors(
            indexer,
            source_docs,
            batch_size,
            "port dump files",
            total_count=total_count,
            include_tags=True,
        )
    )
    print(
        "Kvrocks rebuild complete: "
        f"processed={processed_count} indexed={indexed_count} errors={error_count}",
        flush=True,
    )
    return processed_count, indexed_count, error_count


def main(argv=None):
    """
    Run full port dump re-import.
    """
    args = parse_args(argv)
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory not found: {input_dir}")

    batch_size = load_tool_config(args.batch_size)
    validate_out_targets(
        skip_meili=args.skip_meili,
        skip_kvrocks=args.skip_kvrocks,
    )
    if batch_size <= 0:
        raise SystemExit("--batch-size must be >= 1")

    total_count = sum(1 for _json_file in iter_json_files(input_dir))
    if total_count <= 0:
        raise SystemExit(f"No JSON documents found in {input_dir}")

    print(
        "Starting full port dump re-import: "
        f"input_dir={input_dir} docs={total_count} batch_size={batch_size} "
        f"workers={args.workers} meili_queue_depth={args.meili_queue_depth} "
        f"meili_replace_mode={args.meili_replace_mode}",
        flush=True,
    )
    print_out_targets(
        skip_meili=args.skip_meili,
        skip_kvrocks=args.skip_kvrocks,
    )

    if not args.skip_kvrocks:
        prepare_index_kvrocks_runtime()
    if not args.skip_meili:
        replace_meili_from_dump(
            input_dir,
            batch_size,
            total_count,
            args.meili_timeout_ms,
            args.meili_interval_ms,
            args.meili_queue_depth,
            args.meili_replace_mode,
        )
    if not args.skip_kvrocks:
        rebuild_kvrocks_from_dump(input_dir, batch_size, args.workers, total_count)

    print("Port dump re-import complete", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted; forced stop.", file=sys.stderr, flush=True)
        raise SystemExit(130)
