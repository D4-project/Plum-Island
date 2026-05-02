#!/bin/env python
"""
This script will import the locals json data exported from meilidb export
into the Kvrocks for idexation.

"""
import argparse
import json
import logging
import multiprocessing
import os
import signal
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
WEBAPP_DIR = BASE_DIR.parent / "webapp"
UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(UTILS_DIR))

INDEX_FIELDS = [
    "net",
    "fqdn",
    "fqdn_requested",
    "host",
    "domain",
    "domain_requested",
    "tld",
    "tag",
    "port",
    "http_title",
    "http_favicon_path",
    "http_favicon_mmhash",
    "http_favicon_md5",
    "http_favicon_sha256",
    "http_cookiename",
    "http_etag",
    "http_server",
    "x509_issuer",
    "x509_md5",
    "x509_sha1",
    "x509_sha256",
    "x509_subject",
    "x509_san",
    "banner",
]
REBUILD_KEY_PATTERNS = [
    "doc:*",
    "uid:*",
    "ip:*",
]

DEFAULT_BATCH_SIZE = 1000
DEFAULT_WORKERS = max(1, (os.cpu_count() or 1) - 1)
PROGRESS_EVERY = 1000
config = {}
KVROCKS_PORT = None
KVROCKS_HOST = None
BATCH_SIZE = DEFAULT_BATCH_SIZE
PARSER_CONF = {}
KVrocksIndexer = None
parse_json = None
fetch_tlds = None
TAG_RUNTIME = {}
WORKER_SEEN_SNAPSHOT = None
WORKER_TAG_RULES = None
STOP_REQUESTED = False


def suppress_connection_debug_logs():
    """
    Keep noisy HTTP/TCP client debug logs out of CLI output.
    """
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def request_graceful_stop(_signum, _frame):
    """
    Ask the main indexing loop to stop after flushing the current batch.
    """
    global STOP_REQUESTED

    if STOP_REQUESTED:
        raise KeyboardInterrupt

    STOP_REQUESTED = True
    print(
        "Ctrl+C received; finishing current batch before stopping. "
        "Press Ctrl+C again to force stop.",
        file=sys.stderr,
        flush=True,
    )


def install_graceful_interrupt_handler():
    """
    Route Ctrl+C through the main loop for graceful shutdown.
    """
    signal.signal(signal.SIGINT, request_graceful_stop)


def load_config():
    """
    Load tool config after CLI parsing, so help can run without side effects.
    """
    global config, KVROCKS_PORT, KVROCKS_HOST, BATCH_SIZE, PARSER_CONF

    import yaml  # pylint: disable=import-outside-toplevel

    with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    KVROCKS_PORT = config.get("OUT_KVROCKS_PORT")
    KVROCKS_HOST = config.get("OUT_KVROCKS_HOST")
    BATCH_SIZE = int(config.get("KVROCKS_BATCH_SIZE", DEFAULT_BATCH_SIZE))
    PARSER_CONF = {
        "ONLINETLD": config.get("ONLINETLD", config.get("PARSER_ONLINETLD", False)),
        "TLDS": [],
        "TLDADD": config.get("TLDADD", config.get("PARSER_TLDADD", ["local"])),
    }


def load_runtime_dependencies(retag=False):
    """
    Import runtime dependencies after help handling.
    """
    global KVrocksIndexer, TAG_RUNTIME, parse_json, fetch_tlds

    if retag:
        sys.path.insert(0, str(WEBAPP_DIR))

        from app import app, db  # pylint: disable=import-outside-toplevel
        from app.models import TagRules  # pylint: disable=import-outside-toplevel
        from app.utils.kvrocks import (  # pylint: disable=import-outside-toplevel
            KVrocksIndexer as RuntimeKVrocksIndexer,
        )
        from app.utils.mutils import (  # pylint: disable=import-outside-toplevel
            fetch_tlds as runtime_fetch_tlds,
        )
        from app.utils.result_parser import (  # pylint: disable=import-outside-toplevel
            parse_json as runtime_parse_json,
        )
        from app.utils.tagrules import (  # pylint: disable=import-outside-toplevel
            compile_tag_rule_records,
        )

        TAG_RUNTIME = {
            "app": app,
            "db": db,
            "TagRules": TagRules,
            "compile_tag_rule_records": compile_tag_rule_records,
        }
    else:
        from kvrocks import (  # pylint: disable=import-outside-toplevel
            KVrocksIndexer as RuntimeKVrocksIndexer,
        )
        from mutils import (  # pylint: disable=import-outside-toplevel
            fetch_tlds as runtime_fetch_tlds,
        )
        from result_parser import (  # pylint: disable=import-outside-toplevel
            parse_json as runtime_parse_json,
        )
        TAG_RUNTIME = {}

    KVrocksIndexer = RuntimeKVrocksIndexer
    parse_json = runtime_parse_json
    fetch_tlds = runtime_fetch_tlds


def get_config_value(*names, default=None):
    """
    Return the first configured value for a list of key names.
    """
    for name in names:
        value = config.get(name)
        if value not in (None, ""):
            return value
    return default


def load_active_tag_rules():
    """
    Compile active DB-backed tag rules for parser-side tag computation.
    """
    app = TAG_RUNTIME["app"]
    db = TAG_RUNTIME["db"]
    TagRules = TAG_RUNTIME["TagRules"]
    compile_tag_rule_records = TAG_RUNTIME["compile_tag_rule_records"]

    with app.app_context():
        active_rules = (
            db.session.query(TagRules)
            .filter(TagRules.active == True)
            .order_by(TagRules.id.asc())
            .all()
        )
        return compile_tag_rule_records(active_rules), len(active_rules)


def json_import(json_file, seen_snapshot=None, tag_rules=None):
    """
    Load and parse one dumped JSON document for Kvrocks.
    """
    with open(json_file, "r", encoding="utf-8") as json_handle:
        doc = json.loads(json_handle.read())
        parsed_doc = parse_json(doc, PARSER_CONF, tag_rules=tag_rules)
        apply_seen_snapshot(parsed_doc, seen_snapshot)
        return parsed_doc


def parse_meili_document(doc, seen_snapshot=None, tag_rules=None):
    """
    Parse one Meilisearch document for Kvrocks indexing.
    """
    parsed_doc = parse_json(dict(doc), PARSER_CONF, tag_rules=tag_rules)
    apply_seen_snapshot(parsed_doc, seen_snapshot)
    return parsed_doc


def init_parse_worker(parser_conf, seen_snapshot, tag_rules):
    """
    Initialize one parser worker process with read-only parser state.
    """
    global PARSER_CONF, WORKER_SEEN_SNAPSHOT, WORKER_TAG_RULES

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    suppress_connection_debug_logs()
    load_runtime_dependencies(retag=False)
    PARSER_CONF = dict(parser_conf)
    WORKER_SEEN_SNAPSHOT = seen_snapshot
    WORKER_TAG_RULES = tag_rules


def parse_json_file_worker(json_file):
    """
    Parse one JSON dump file in a worker process.
    """
    try:
        return json_import(
            json_file,
            seen_snapshot=WORKER_SEEN_SNAPSHOT,
            tag_rules=WORKER_TAG_RULES,
        ), None
    except Exception as error:  # pylint: disable=broad-except
        return None, f"[WARN] Unable to parse {json_file}: {error}"


def parse_meili_document_worker(meili_doc):
    """
    Parse one Meilisearch document in a worker process.
    """
    try:
        return parse_meili_document(
            meili_doc,
            seen_snapshot=WORKER_SEEN_SNAPSHOT,
            tag_rules=WORKER_TAG_RULES,
        ), None
    except Exception as error:  # pylint: disable=broad-except
        doc_id = dict(meili_doc).get("id", "<unknown>")
        return None, f"[WARN] Unable to parse Meili document {doc_id}: {error}"


def apply_seen_snapshot(parsed_doc, seen_snapshot):
    """
    Preserve historical first_seen/last_seen values during a rebuild.
    """
    if not seen_snapshot:
        return

    uid = parsed_doc.get("uid")
    if uid not in seen_snapshot:
        return

    snapshot_first_seen, snapshot_last_seen = seen_snapshot[uid]
    doc_first_seen, doc_last_seen = KVrocksIndexer.normalize_seen_range(
        parsed_doc.get("first_seen"), parsed_doc.get("last_seen")
    )

    first_seen_candidates = [
        value
        for value in (snapshot_first_seen, doc_first_seen, doc_last_seen)
        if value is not None
    ]
    last_seen_candidates = [
        value
        for value in (snapshot_last_seen, doc_first_seen, doc_last_seen)
        if value is not None
    ]
    if first_seen_candidates:
        parsed_doc["first_seen"] = min(first_seen_candidates)
    if last_seen_candidates:
        parsed_doc["last_seen"] = max(last_seen_candidates)


def iter_json_files(input_dir):
    """
    Iterate every dumped Meilisearch JSON document.
    """
    for json_file in sorted(input_dir.rglob("*.json")):
        if json_file.is_file():
            yield json_file


def fetch_meili_page(index, page_size, offset):
    """
    Fetch one Meilisearch page.
    """
    print(
        f"Fetching Meili documents offset={offset} limit={page_size}",
        flush=True,
    )
    documents = index.get_documents({"limit": page_size, "offset": offset})
    total_count = get_meili_total_count(documents)
    results = [dict(result) for result in getattr(documents, "results", []) or []]
    return results, total_count


def get_meili_total_count(documents):
    """
    Return total document count from a Meilisearch get_documents response.
    """
    for attribute in ("total", "totalHits", "estimatedTotalHits"):
        value = getattr(documents, attribute, None)
        if value is not None:
            return int(value)
    return None


def iter_meili_documents(index, page_size, first_results=None):
    """
    Yield Meilisearch documents page by page in read-only mode.
    """
    offset = 0
    if first_results is not None:
        results = first_results
        for result in results:
            yield dict(result)
        offset += len(results)

    while True:
        results, _total_count = fetch_meili_page(index, page_size, offset)
        if not results:
            break

        for result in results:
            yield dict(result)

        offset += len(results)


def snapshot_seen_values(indexer):
    """
    Snapshot existing document seen ranges before rebuilding keys.
    """
    snapshot = {}
    for key in indexer.r.scan_iter(match="doc:*", count=1000):
        uid = key.split("doc:", 1)[1]
        data = indexer.r.hgetall(key)
        first_seen, last_seen = KVrocksIndexer.normalize_seen_range(
            data.get("first_seen"), data.get("last_seen")
        )
        if first_seen is not None and last_seen is not None:
            snapshot[uid] = (first_seen, last_seen)
    return snapshot


def delete_keys_by_pattern(redis_client, pattern, batch_size=1000):
    """
    Delete keys matching one pattern without blocking on KEYS.
    """
    deleted = 0
    batch = []
    for key in redis_client.scan_iter(match=pattern, count=batch_size):
        batch.append(key)
        if len(batch) >= batch_size:
            deleted += redis_client.delete(*batch)
            batch = []
    if batch:
        deleted += redis_client.delete(*batch)
    return deleted


def clean_tag_indexes(indexer):
    """
    Remove existing tag indexes before recomputing tags for parsed documents.
    """
    print("Deleting existing Plum Kvrocks tag indexes", flush=True)
    deleted = 0
    for pattern in ("tag:*", "tags:*"):
        deleted_for_pattern = delete_keys_by_pattern(indexer.r, pattern)
        deleted += deleted_for_pattern
        if deleted_for_pattern:
            print(f"Deleted {deleted_for_pattern} keys matching {pattern}", flush=True)
    print(f"Deleted {deleted} tag keys before tag reparse", flush=True)
    return deleted


def rebuild_kvrocks(indexer, include_tags=False):
    """
    Remove known Plum index keys while preserving seen timestamps in memory.
    """
    print("Snapshotting existing doc:{uid} timestamps", flush=True)
    seen_snapshot = snapshot_seen_values(indexer)
    print(f"Snapshot contains {len(seen_snapshot)} documents", flush=True)

    print("Deleting known Plum Kvrocks index keys", flush=True)
    deleted = indexer.r.delete(
        "all_ips",
        "all_uids",
        "first_seen_index",
        "last_seen_index",
    )
    patterns = list(REBUILD_KEY_PATTERNS)
    for field in INDEX_FIELDS:
        if field == "tag" and not include_tags:
            continue
        patterns.append(f"{field}:*")
        patterns.append(f"{field}s:*")

    for pattern in patterns:
        deleted_for_pattern = delete_keys_by_pattern(indexer.r, pattern)
        deleted += deleted_for_pattern
        if deleted_for_pattern:
            print(f"Deleted {deleted_for_pattern} keys matching {pattern}", flush=True)

    print(f"Deleted {deleted} keys before rebuild", flush=True)
    return seen_snapshot


def parse_args(argv=None):
    """
    Parse CLI arguments for Kvrocks indexing.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=(
            "Import Meilisearch dump JSON files into Kvrocks. Use --retag with "
            "--rebuild or --rebuild-from-meili to recompute active Tag Rules "
            "and clean existing tag indexes."
        )
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Rebuild known Plum Kvrocks keys while preserving first_seen/last_seen.",
    )
    parser.add_argument(
        "--rebuild-from-meili",
        action="store_true",
        dest="rebuild_from_meili",
        help=(
            "Rebuild known Plum Kvrocks keys directly from Meilisearch while "
            "preserving first_seen/last_seen."
        ),
    )
    parser.add_argument(
        "--retag",
        action="store_true",
        help=(
            "With --rebuild or --rebuild-from-meili, clean tag indexes and "
            "recompute tags from all active Tag Rules."
        ),
    )
    parser.add_argument(
        "--input-dir",
        default=str(BASE_DIR / "meili_dump"),
        help="Directory containing dumped Meilisearch JSON files.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Number of parsed documents to send per Kvrocks batch.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            "Parser worker processes. Use 1 to disable multiprocessing. "
            f"Default: {DEFAULT_WORKERS}."
        ),
    )
    if not argv:
        parser.print_help()
        raise SystemExit(0)

    args = parser.parse_args(argv)
    if args.retag and not (args.rebuild or args.rebuild_from_meili):
        parser.error("--retag requires --rebuild or --rebuild-from-meili")
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    return args


def format_progress_count(count, total_count=None):
    """
    Format a progress count with optional total and percentage.
    """
    if total_count:
        percentage = (count / total_count) * 100
        return f"{count}/{total_count} ({percentage:.1f}%)"
    return str(count)


def index_parsed_documents(
    indexer,
    parsed_documents,
    batch_size,
    progress_label,
    total_count=None,
    include_tags=False,
):
    """
    Index a stream of already parsed Kvrocks documents.
    """
    objects_to_index = []
    processed_count = 0
    indexed_count = 0

    try:
        for parsed_doc in parsed_documents:
            if STOP_REQUESTED:
                break

            processed_count += 1
            objects_to_index.append(parsed_doc)

            if processed_count % PROGRESS_EVERY == 0:
                print(
                    f"Processed {format_progress_count(processed_count, total_count)} "
                    f"{progress_label}; "
                    f"indexed={format_progress_count(indexed_count, total_count)}; "
                    f"pending_batch={len(objects_to_index)}",
                    flush=True,
                )

            if len(objects_to_index) >= batch_size:
                print(
                    f"Indexing batch of {len(objects_to_index)} documents...",
                    flush=True,
                )
                indexer.add_documents_batch(objects_to_index, include_tags=include_tags)
                indexed_count += len(objects_to_index)
                print(
                    f"Indexed {format_progress_count(indexed_count, total_count)} "
                    "documents",
                    flush=True,
                )
                objects_to_index = []

            if STOP_REQUESTED:
                break
    except KeyboardInterrupt:
        if STOP_REQUESTED:
            raise
        request_graceful_stop(None, None)

    if STOP_REQUESTED:
        close_iterator = getattr(parsed_documents, "close", None)
        if close_iterator:
            close_iterator()
        print(
            "Graceful stop requested; flushing parsed pending documents.",
            file=sys.stderr,
            flush=True,
        )

    if objects_to_index:
        print(f"Indexing final batch of {len(objects_to_index)} documents...", flush=True)
        indexer.add_documents_batch(objects_to_index, include_tags=include_tags)
        indexed_count += len(objects_to_index)

    return processed_count, indexed_count


def multiprocessing_chunksize(batch_size, workers):
    """
    Return a bounded chunksize for parser worker scheduling.
    """
    return max(1, min(100, batch_size // max(workers * 4, 1) or 1))


def parsed_documents_from_files(
    input_dir,
    seen_snapshot,
    tag_rules=None,
    workers=1,
    batch_size=DEFAULT_BATCH_SIZE,
):
    """
    Yield parsed Kvrocks documents from a Meilisearch JSON dump directory.
    """
    if workers > 1:
        chunksize = multiprocessing_chunksize(batch_size, workers)
        print(
            f"Parsing files with {workers} worker processes "
            f"(chunksize={chunksize})",
            flush=True,
        )
        with multiprocessing.Pool(
            processes=workers,
            initializer=init_parse_worker,
            initargs=(PARSER_CONF, seen_snapshot, tag_rules),
        ) as pool:
            yield from pool.imap_unordered(
                parse_json_file_worker,
                iter_json_files(input_dir),
                chunksize=chunksize,
            )
        return

    for json_file in iter_json_files(input_dir):
        try:
            yield json_import(json_file, seen_snapshot, tag_rules=tag_rules), None
        except Exception as error:  # pylint: disable=broad-except
            yield None, f"[WARN] Unable to parse {json_file}: {error}"


def build_meili_index():
    """
    Build the configured Meilisearch index client.
    """
    import meilisearch  # pylint: disable=import-outside-toplevel

    meili_url = get_config_value("IN_MEILI_URL", "MEILI_URL")
    meili_api_key = get_config_value(
        "IN_MEILI_API_KEY",
        "IN MEILI_API_KEY",
        "MEILI_API_KEY",
    )
    index_name = get_config_value("INDEX_NAME", default="plum")

    if not meili_url:
        raise SystemExit("Missing IN_MEILI_URL or MEILI_URL in tools/config.yaml")

    client = meilisearch.Client(meili_url, meili_api_key)
    index = client.index(index_name)
    return meili_url, index_name, index


def parsed_documents_from_meili(
    index,
    seen_snapshot,
    batch_size,
    first_results=None,
    tag_rules=None,
    workers=1,
):
    """
    Yield parsed Kvrocks documents from Meilisearch directly.
    """
    if workers > 1:
        chunksize = multiprocessing_chunksize(batch_size, workers)
        print(
            f"Parsing Meili documents with {workers} worker processes "
            f"(chunksize={chunksize})",
            flush=True,
        )
        with multiprocessing.Pool(
            processes=workers,
            initializer=init_parse_worker,
            initargs=(PARSER_CONF, seen_snapshot, tag_rules),
        ) as pool:
            yield from pool.imap_unordered(
                parse_meili_document_worker,
                iter_meili_documents(index, batch_size, first_results=first_results),
                chunksize=chunksize,
            )
        return

    for meili_doc in iter_meili_documents(index, batch_size, first_results=first_results):
        try:
            yield parse_meili_document(
                meili_doc,
                seen_snapshot,
                tag_rules=tag_rules,
            ), None
        except Exception as error:  # pylint: disable=broad-except
            doc_id = dict(meili_doc).get("id", "<unknown>")
            yield None, f"[WARN] Unable to parse Meili document {doc_id}: {error}"


def index_documents_with_errors(
    indexer,
    documents_with_errors,
    batch_size,
    progress_label,
    total_count=None,
    include_tags=False,
):
    """
    Index parsed documents while counting parse errors from the source iterator.
    """
    error_count = 0

    def valid_documents():
        nonlocal error_count
        try:
            for parsed_doc, error in documents_with_errors:
                if STOP_REQUESTED:
                    break
                if error:
                    error_count += 1
                    print(error, flush=True)
                    continue
                yield parsed_doc
        finally:
            close_iterator = getattr(documents_with_errors, "close", None)
            if close_iterator:
                close_iterator()

    processed_count, indexed_count = index_parsed_documents(
        indexer,
        valid_documents(),
        batch_size,
        progress_label,
        total_count=total_count,
        include_tags=include_tags,
    )
    return processed_count + error_count, indexed_count, error_count


def main():
    """
    Rebuild or update the Kvrocks indexes from Meilisearch documents.
    """
    suppress_connection_debug_logs()
    args = parse_args()
    load_config()
    if args.batch_size is None:
        args.batch_size = BATCH_SIZE
    load_runtime_dependencies(retag=args.retag)
    suppress_connection_debug_logs()

    input_dir = Path(args.input_dir)
    indexer = KVrocksIndexer(KVROCKS_HOST, KVROCKS_PORT)
    meili_index = None
    first_meili_results = None
    total_count = None
    tag_rules = None

    if PARSER_CONF["ONLINETLD"]:
        PARSER_CONF["TLDS"] = fetch_tlds()
    else:
        PARSER_CONF["TLDS"] = config.get("TLDS", config.get("PARSER_TLDS", []))

    if args.retag:
        tag_rules, active_rule_count = load_active_tag_rules()
        print(
            f"Loaded {len(tag_rules)} compiled tag rules from "
            f"{active_rule_count} active DB rows",
            flush=True,
        )

    if args.rebuild_from_meili:
        meili_url, index_name, meili_index = build_meili_index()
        print(
            f"Reading source documents from {meili_url} / index={index_name}",
            flush=True,
        )
        first_meili_results, total_count = fetch_meili_page(
            meili_index,
            args.batch_size,
            0,
        )
        if not first_meili_results:
            raise SystemExit("Meilisearch returned no documents; refusing to rebuild Kvrocks")

    seen_snapshot = (
        rebuild_kvrocks(indexer, include_tags=args.retag)
        if args.rebuild or args.rebuild_from_meili
        else None
    )

    if args.rebuild_from_meili:
        source_docs = parsed_documents_from_meili(
            meili_index,
            seen_snapshot,
            args.batch_size,
            first_results=first_meili_results,
            tag_rules=tag_rules,
            workers=args.workers,
        )
        progress_label = "Meili documents"
    else:
        total_count = sum(1 for _json_file in iter_json_files(input_dir))
        source_docs = parsed_documents_from_files(
            input_dir,
            seen_snapshot,
            tag_rules=tag_rules,
            workers=args.workers,
            batch_size=args.batch_size,
        )
        progress_label = "files"

    install_graceful_interrupt_handler()
    processed_count, indexed_count, error_count = index_documents_with_errors(
        indexer,
        source_docs,
        args.batch_size,
        progress_label,
        total_count=total_count,
        include_tags=args.retag,
    )

    print(
        "Kvrocks indexing complete: "
        f"processed={processed_count} indexed={indexed_count} errors={error_count}",
        flush=True,
    )
    if STOP_REQUESTED:
        raise SystemExit(130)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted; forced stop.", file=sys.stderr, flush=True)
        raise SystemExit(130)
