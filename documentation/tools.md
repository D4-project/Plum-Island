# Tools

The `tools/` directory contains operational helpers for imports, indexing, searches, and diagnostics.
Run tools from the repository root unless noted otherwise.

Most Python tools expect the project virtual environment:

```bash
.venv/bin/python tools/<script>.py ...
```

## Configuration

Several tools read `tools/config.yaml`.
Start from the sample:

```bash
cp tools/config.yaml.sample tools/config.yaml
```

Important settings:

- `IN_MEILI_URL`, `IN_MEILI_API_KEY`, `INDEX_NAME`: Meilisearch input index
- `IN_KVROCKS_HOST`, `IN_KVROCKS_PORT`: Kvrocks index used by imports/search dumps
- `OUT_KVROCKS_HOST`, `OUT_KVROCKS_PORT`: Kvrocks output used by some export helpers
- `PLUMISLAND`, `PLUMAPIUSER`, `PLUMAPIPWD`: API access for webapp import helpers

## Tag tools

### `import_tags.py`

Import YAML tag rules from `webapp/tags/` into the SQLite application database.

```bash
.venv/bin/python tools/import_tags.py
```

Useful options:

```bash
.venv/bin/python tools/import_tags.py --dry-run
.venv/bin/python tools/import_tags.py --tags-file webapp/tags/hashicorp_vault.yaml
.venv/bin/python tools/import_tags.py --tags-dir webapp/tags
.venv/bin/python tools/import_tags.py --flush_db
```

Version policy:

- new rules are inserted
- existing rules are replaced only when the YAML version is older than the DB timestamp
- YAML rules without `version` are considered older than DB rules

### `reindex_tagrule.py`

Recompute tags in Kvrocks after tag rule changes.

Reindex all active rules:

```bash
.venv/bin/python tools/reindex_tagrule.py --allrules
```

Reindex from one tag rule id:

```bash
.venv/bin/python tools/reindex_tagrule.py 42
```

Flush existing tag indexes before recomputing:

```bash
.venv/bin/python tools/reindex_tagrule.py --allrules --flush
```

List complete tag keys currently indexed in Kvrocks:

```bash
.venv/bin/python tools/reindex_tagrule.py --list_tags
```

## Search and dump tools

### `dump_object.py`

Dump distinct indexed Kvrocks values for one exact indexed field.
Output is CSV:

```text
count,value
```

Examples:

```bash
.venv/bin/python tools/dump_object.py http_title
.venv/bin/python tools/dump_object.py http_server
.venv/bin/python tools/dump_object.py http_cookiename
.venv/bin/python tools/dump_object.py banner
```

List dumpable fields:

```bash
.venv/bin/python tools/dump_object.py --list-dumpable
```

The field name must be the real indexed Kvrocks field name. No aliases are accepted.

### `kvrocks_search.py`

Developer/demo script showing how to call `KVrocksIndexer.get_uids_by_criteria()`.
It is useful as an example for exact, prefix, substring, IP, network, and port criteria.

### `test_parse.py`

Parse one Meilisearch JSON document and print the parsed structure with computed tags.

```bash
.venv/bin/python tools/test_parse.py meili_dump/a/<uid>.json
```

## Indexing tools

### `dump_meilidb.py`

Export all documents from the configured Meilisearch index to `meili_dump/`.
Each document is written as one JSON file grouped by the first character of its UID.

Run from `tools/` because the script reads `config.yaml` from the current directory:

```bash
cd tools
../.venv/bin/python dump_meilidb.py
```

### `index_kvrocks.py`

Import dumped Meilisearch JSON documents into Kvrocks.

```bash
.venv/bin/python tools/index_kvrocks.py --input-dir tools/meili_dump
```

Rebuild known Plum Kvrocks keys while preserving `first_seen` and `last_seen`:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild --input-dir tools/meili_dump
```

Batch size can be adjusted:

```bash
.venv/bin/python tools/index_kvrocks.py --batch-size 500
```

### `first_seen_csv.py`

Export and restore `first_seen` values across Kvrocks rebuilds.
This exists because `first_seen` is historical Kvrocks state and cannot be fully reparsed from Meilisearch documents.

Export from `IN_KVROCKS_HOST` / `IN_KVROCKS_PORT`:

```bash
.venv/bin/python tools/first_seen_csv.py --export first_seen.csv
```

Import into `OUT_KVROCKS_HOST` / `OUT_KVROCKS_PORT`:

```bash
.venv/bin/python tools/first_seen_csv.py --import first_seen.csv
```

Validate the CSV without writing:

```bash
.venv/bin/python tools/first_seen_csv.py --import first_seen.csv --dry-run
```

CSV columns:

```text
uid,ip,first_seen,last_seen
```

Only `uid` and `first_seen` are required for import.
The import updates `doc:{uid}.first_seen` and `first_seen_index`.
It does not overwrite `last_seen`.
The tool prints the expected total first, then progress every 1000 processed records.

### `index_meili.py`

Import JSON documents from `meili_dump/` into Meilisearch.
This is a low-level recovery helper with hardcoded connection defaults in the script.
Review the script before use.

## Target and FQDN tools

### `import_fqdns.py`

Bulk-import newline-delimited targets through the Plum Island API.
The input file can contain FQDNs, IPs, and CIDR ranges.

```bash
.venv/bin/python tools/import_fqdns.py --file targets.txt
```

The tool authenticates with `PLUMISLAND`, `PLUMAPIUSER`, and `PLUMAPIPWD` from `tools/config.yaml`.

### `last_fqdns.py`

Extract uniqure FQDNs seen during the last N hours from Kvocks.

```bash
cd tools
../.venv/bin/python last_fqdns.py --hours 24
```

Optionally resolve every FQDN:

```bash
cd tools
../.venv/bin/python last_fqdns.py --hours 24 --resolve yes
```

This tool currently expects to be executed from `tools/` because it reads `config.yaml` and imports utility modules with relative paths.

## Notes

- `tools/config.yaml` can contain credentials. Do not commit production secrets.
- `tools/q` and `tools/title` are local scratch files, not maintained CLI tools.
- Prefer `--dry-run` when available before writing to the database or indexes.
