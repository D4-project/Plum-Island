#!/bin/env python
"""
Dump indexed http_server values from IN_KVROCKS as raw CSV on stdout.
"""

from pathlib import Path
import sys

import yaml

BASE_DIR = Path(__file__).resolve().parent
UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(UTILS_DIR))

from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position


with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as config_file:
    config = yaml.safe_load(config_file) or {}


def main():
    """
    Print `count,http_server` lines to stdout.
    """
    kvrocks_host = config.get("IN_KVROCKS_HOST", "localhost")
    kvrocks_port = config.get("IN_KVROCKS_PORT", 6666)
    indexer = KVrocksIndexer(kvrocks_host, kvrocks_port)

    results = []
    for key in indexer.r.scan_iter(match="http_server:*", count=1000):
        value = key.split(":", 1)[1]
        if not value:
            continue
        count = indexer.r.scard(key)
        results.append((count, value))

    for count, value in sorted(results, key=lambda item: (-item[0], item[1])):
        print(f"{count},{value}")


if __name__ == "__main__":
    main()
