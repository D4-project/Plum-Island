#!/usr/bin/env python3
"""Fill InfoIP protocol/port indexes for existing Kvrocks documents."""

import argparse
from pathlib import Path
import sys

import meilisearch
import yaml

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR.parent / "webapp" / "app" / "utils"))

from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position,import-error
from result_parser import port_protocol_values  # pylint: disable=wrong-import-position,import-error


def chunks(items, size):
    """Yield bounded batches from an iterator."""
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def backfill(indexer, index, batch_size, dry_run=False):
    """Fetch missing protocol pairs by UID and update only this Kvrocks field."""
    checked = updated = missing = 0
    for uids in chunks(indexer.r.sscan_iter("all_uids", count=batch_size), batch_size):
        pipe = indexer.r.pipeline(transaction=False)
        for uid in uids:
            pipe.exists(f"port_protocols:{uid}")
        pending = [uid for uid, exists in zip(uids, pipe.execute()) if not exists]
        checked += len(uids)
        if not pending:
            continue
        docs = []
        for result in index.get_documents(
            {"ids": pending, "fields": ["id", "body.ports"], "limit": len(pending)}
        ).results:
            raw_doc = dict(result)
            values = port_protocol_values(raw_doc)
            if values:
                docs.append({"uid": raw_doc["id"], "port_protocol": values})
        missing += len(pending) - len(docs)
        if docs and not dry_run:
            indexer.replace_field_values_batch("port_protocol", docs)
        updated += len(docs)
        print(
            f"Checked {checked}; {'would update' if dry_run else 'updated'} {updated}; missing {missing}",
            flush=True,
        )
    return checked, updated, missing


def main(argv=None):
    """Read the shared tools config, then backfill existing UIDs in batches."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.batch_size < 1 or args.batch_size > 1000:
        parser.error("--batch-size must be between 1 and 1000")

    with open(BASE_DIR / "config.yaml", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}
    for key in ("IN_MEILI_URL", "OUT_KVROCKS_HOST", "OUT_KVROCKS_PORT"):
        if not config.get(key):
            parser.error(f"Missing {key} in tools/config.yaml")
    indexer = KVrocksIndexer(config["OUT_KVROCKS_HOST"], config["OUT_KVROCKS_PORT"])
    index = meilisearch.Client(
        config["IN_MEILI_URL"], config.get("IN_MEILI_API_KEY")
    ).index(config.get("INDEX_NAME", "plum"))
    backfill(indexer, index, args.batch_size, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
