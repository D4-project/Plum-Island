#!/bin/env python
"""
This script will import json data exported from meilidb export
into the Kvrocks for idexation.

"""
import os
import json
import sys
import yaml

sys.path.append("../webapp/app/utils")  # parent of webapp
from kvrocks import KVrocksIndexer
from result_parser import parse_json
from mutils import fetch_tlds

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
KVROCKS_PORT = config.get("OUT_KVROCKS_PORT")
KVROCKS_HOST = config.get("OUT_KVROCKS_HOST")


def json_import(json_file):
    print(f"Importing {json_file}")
    with open(json_file, "r", encoding="utf-8") as f:
        doc = json.loads(f.read())
        return parse_json(doc)


INPUT_DIR = "meili_dump"
indexer = KVrocksIndexer(KVROCKS_HOST, KVROCKS_PORT)
max_per_folder = 10000
max_per_folder = 1
tlds = fetch_tlds()
for folder in "abcdef0123456789":
    objects_to_index = []
    path = os.path.join(INPUT_DIR, folder)
    for file in os.listdir(path):
        if file.endswith(".json"):
            objects_to_index.append(json_import(os.path.join(INPUT_DIR, folder, file)))
            if len(objects_to_index) == max_per_folder:
                indexer.add_documents_batch(objects_to_index, tlds)
                objects_to_index = []
    # finally
    indexer.add_documents_batch(objects_to_index)
