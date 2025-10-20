#!/bin/env python
'''
    This script will upload to meili a json extract

'''
import os
import json
from meilisearch import Client

MEILI_IP = "127.0.0.1"
MEILI_DB = "plum"
INPUT_DIR = "meili_dump"
MASTER_KEY = "YouNeedToChangeMeInProduction"
client = Client(f"http://{MEILI_IP}:7700", MASTER_KEY)  # remplace par ta clé si nécessaire
index = client.index(MEILI_DB)

def object_to_meili(filename):
    """Lit un fichier JSON et l'ajoute à Meilisearch"""
    with open(filename, "r", encoding="utf-8") as f:
        obj = json.load(f)
    # obj doit être un dict ou une liste de dicts
    if isinstance(obj, dict):
        index.add_documents([obj])
    elif isinstance(obj, list):
        index.add_documents(obj)
    else:
        print(f"Type not suported in {filename}: {type(obj)}")

# do all folders a-f et 0-9
for folder in "abcdef0123456789":
    print(f"parsing {folder}")
    path = os.path.join(INPUT_DIR, folder)
    if not os.path.isdir(path):
        continue
    for file in os.listdir(path):
        if file.endswith(".json"):
            object_to_meili(os.path.join(path, file))

