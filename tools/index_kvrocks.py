#!/bin/env python
"""
This script will import the locals json data exported from meilidb export
into the Kvrocks for idexation.

"""
import argparse
import json
import sys
import yaml
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(UTILS_DIR))

from kvrocks import KVrocksIndexer
from result_parser import parse_json
from mutils import fetch_tlds

INDEX_FIELDS = [
    "net",
    "fqdn",
    "host",
    "domain",
    "tld",
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

with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)
KVROCKS_PORT = config.get("OUT_KVROCKS_PORT")
KVROCKS_HOST = config.get("OUT_KVROCKS_HOST")
BATCH_SIZE = int(config.get("KVROCKS_BATCH_SIZE", 1000))
PROGRESS_EVERY = 1000
PARSER_CONF = {
    "ONLINETLD": config.get("ONLINETLD", config.get("PARSER_ONLINETLD", False)),
    "TLDS": [],
    "TLDADD": config.get("TLDADD", config.get("PARSER_TLDADD", ["local"])),
}


def json_import(json_file, seen_snapshot=None):
    with open(json_file, "r", encoding="utf-8") as f:
        doc = json.loads(f.read())
        parsed_doc = parse_json(doc, PARSER_CONF)
        apply_seen_snapshot(parsed_doc, seen_snapshot)
        return parsed_doc


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


def rebuild_kvrocks(indexer):
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
        patterns.append(f"{field}:*")
        patterns.append(f"{field}s:*")

    for pattern in patterns:
        deleted_for_pattern = delete_keys_by_pattern(indexer.r, pattern)
        deleted += deleted_for_pattern
        if deleted_for_pattern:
            print(f"Deleted {deleted_for_pattern} keys matching {pattern}", flush=True)

    print(f"Deleted {deleted} keys before rebuild", flush=True)
    return seen_snapshot


def parse_args():
    parser = argparse.ArgumentParser(
        description="Import Meilisearch dump JSON files into Kvrocks."
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Rebuild known Plum Kvrocks keys while preserving first_seen/last_seen.",
    )
    parser.add_argument(
        "--input-dir",
        default=str(BASE_DIR / "meili_dump"),
        help="Directory containing dumped Meilisearch JSON files.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help="Number of parsed documents to send per Kvrocks batch.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_dir = Path(args.input_dir)
    indexer = KVrocksIndexer(KVROCKS_HOST, KVROCKS_PORT)

    if PARSER_CONF["ONLINETLD"]:
        PARSER_CONF["TLDS"] = fetch_tlds()
    else:
        PARSER_CONF["TLDS"] = config.get("TLDS", config.get("PARSER_TLDS", []))

    seen_snapshot = rebuild_kvrocks(indexer) if args.rebuild else None

    objects_to_index = []
    processed_count = 0
    indexed_count = 0
    error_count = 0
    for json_file in iter_json_files(input_dir):
        processed_count += 1
        try:
            objects_to_index.append(json_import(json_file, seen_snapshot))
        except Exception as error:
            error_count += 1
            print(f"[WARN] Unable to parse {json_file}: {error}")
            continue

        if processed_count % PROGRESS_EVERY == 0:
            print(
                "Processed "
                f"{processed_count} files; indexed={indexed_count}; "
                f"pending_batch={len(objects_to_index)}; errors={error_count}",
                flush=True,
            )

        if len(objects_to_index) >= args.batch_size:
            print(
                f"Indexing batch of {len(objects_to_index)} documents...",
                flush=True,
            )
            indexer.add_documents_batch(objects_to_index)
            indexed_count += len(objects_to_index)
            print(f"Indexed {indexed_count} documents", flush=True)
            objects_to_index = []

    if objects_to_index:
        print(f"Indexing final batch of {len(objects_to_index)} documents...", flush=True)
        indexer.add_documents_batch(objects_to_index)
        indexed_count += len(objects_to_index)

    print(
        "Kvrocks indexing complete: "
        f"processed={processed_count} indexed={indexed_count} errors={error_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
