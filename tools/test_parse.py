#!/bin/env python
import os
import json
import sys
import yaml

sys.path.append("../webapp/app/utils")  # parent of webapp
from result_parser import parse_json

def json_import(json_file):
    print(f"Importing {json_file}")
    with open(json_file, "r", encoding="utf-8") as f:
        doc = json.loads(f.read())
        return parse_json(doc)

INPUT_DIR = "." # meili_dump"
file= sys.argv[1]
folder = file[0]
path = os.path.join(INPUT_DIR, folder)
parsed = json_import(os.path.join(INPUT_DIR, folder, file))
print(json.dumps(parsed, indent=2))
