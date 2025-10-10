#!/bin/env python
"""
This script do a full export of Plum IP database of the meilli instance
Each report is save using the UID
"""

import os
import json
import time
import meilisearch
import yaml

# Configuration
PAGE_SIZE = 5000
OUTPUT_DIR = "meili_dump"


with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
MEILI_URL = config.get("MEILI_URL")
MEILI_API_KEY = config.get("MEILI_API_KEY")
INDEX_NAME = config.get("INDEX_NAME")

# Init client
client = meilisearch.Client(MEILI_URL, MEILI_API_KEY)
index = client.index(INDEX_NAME)


def save_document(doc):
    """
    Save a meili document info json file.
    """
    path = os.path.join(OUTPUT_DIR, doc.id[0])
    os.makedirs(path, exist_ok=True)

    filepath = os.path.join(path, doc.id + ".json")
    with open(filepath, "w", encoding="utf-8") as f:
        # Save as json
        json.dump(dict(doc), f, ensure_ascii=False, indent=2)


def main():
    """
    Iterate the db and collect a bunch of document
    """
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


if __name__ == "__main__":
    main()
