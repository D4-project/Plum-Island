#!/usr/bin/env python3
"""Seed the observed tag catalogue from existing OUT Kvrocks reverse indexes."""

import argparse
from pathlib import Path
import sys

import yaml

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR.parent / "webapp/app/utils"))
from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position


def main():
    """Backfill idempotently without importing Flask or reading document UIDs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=BASE_DIR / "config.yaml")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 10000:
        parser.error("--batch-size must be between 1 and 10000")
    with args.config.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    host = config.get("OUT_KVROCKS_HOST")
    if not host:
        parser.error("Missing OUT_KVROCKS_HOST in tools configuration")
    port = int(config.get("OUT_KVROCKS_PORT") or 6666)
    print(
        f"Scanning existing tag:* keys on {host}:{port} to seed the tag catalogue. "
        "Only tag names and counts are read; document UID sets are not loaded.",
        flush=True,
    )
    indexer = KVrocksIndexer(host, port, socket_timeout=30)
    scanned = indexer.backfill_tag_catalogue(
        args.batch_size,
        progress=lambda count: print(
            f"Progress: tag keys inspected={count}", flush=True
        ),
    )
    print(f"Tag catalogue backfill complete: tag keys inspected={scanned}", flush=True)


if __name__ == "__main__":
    main()
