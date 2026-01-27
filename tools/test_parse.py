#!/bin/env python
import os
import json
import sys

sys.path.append("../webapp/app/utils")  # parent of webapp
from result_parser import parse_json
from mutils import fetch_tlds


def json_import(json_file):
    print(f"Importing {json_file}")
    with open(json_file, "r", encoding="utf-8") as f:
        doc = json.loads(f.read())
        return parse_json(doc, TLDS)


INPUT_DIR = "."  # meili_dump"
file = sys.argv[1]
folder = file[0]
TLDS = fetch_tlds()
path = os.path.join(INPUT_DIR, folder)
parsed = json_import(os.path.join(INPUT_DIR, folder, file))
print(json.dumps(parsed, indent=2))
