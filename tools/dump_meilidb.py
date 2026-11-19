#!/bin/env python
"""
This script do a full export of Plum IP database of the meilli instance
Each report is save using the UID
"""

import argparse
import os
import json
import time
import meilisearch
import yaml

# Configuration
PAGE_SIZE = 5000
OUTPUT_DIR = "meili_dump"


def save_document(doc):
    """
    Save a meili document info json file.
    """
    path = os.path.join(OUTPUT_DIR, doc.id[0])
    os.makedirs(path, exist_ok=True)

    filepath = os.path.join(path, doc.id + ".json")
    with open(filepath, "w", encoding="utf-8") as file2save:
        # Save as json
        json.dump(dict(doc), file2save, ensure_ascii=False, indent=2)


def main(argv=None):
    """
    Iterate the db and collect a bunch of document
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--do-export", action="store_true", help="Export the configured Meilisearch index"
    )
    args = parser.parse_args(argv)
    if not args.do_export:
        parser.print_help()
        return 0

    with open("config.yaml", "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}
    meili_url = config.get("IN_MEILI_URL")
    if not meili_url:
        raise SystemExit("Missing IN_MEILI_URL in tools/config.yaml")
    client = meilisearch.Client(meili_url, config.get("IN_MEILI_API_KEY"))
    index = client.index(config.get("INDEX_NAME"))

    offset = 0
    total_fetched = 0

    while True:
        print(f"Fetching documents offset={offset} ...")
        docs = index.get_documents({"limit": PAGE_SIZE, "offset": offset})
        results = docs.results

        if not results:
            print("Done.. No more documents.")
            break

        for doc in results:
            save_document(doc)
            total_fetched += 1

        offset += PAGE_SIZE
        time.sleep(0.2)

    print(f"\nTotal documents exported : {total_fetched}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
