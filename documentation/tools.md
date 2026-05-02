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
- `OUT_MEILI_URL`, `OUT_MEILI_API_KEY`, `INDEX_NAME`: Meilisearch output index
- `IN_KVROCKS_HOST`, `IN_KVROCKS_PORT`: Kvrocks index used by imports/search dumps
- `OUT_KVROCKS_HOST`, `OUT_KVROCKS_PORT`: Kvrocks output used by some export helpers
- `PLUMISLAND`, `PLUMAPIUSER`, `PLUMAPIPWD`: API access for webapp import helpers

## Tag tools

### `initial_setup.py`

Load initial database content after the Flask database has been created.
`setup.sh` calls this script automatically after `flask fab create-admin`.

It performs three actions:

- create/update security roles from `webapp/security_roles/*.yaml`
- import YAML tag rules from `webapp/tags/` into the application database
- clone/update `https://github.com/D4-project/Plum-Rules-NSE` into `external/Plum-Rules-NSE` and import every `.nse` file into the `nses` table

Manual run:

```bash
.venv/bin/python tools/initial_setup.py
```

Useful options:

```bash
.venv/bin/python tools/initial_setup.py --dry-run
.venv/bin/python tools/initial_setup.py --skip-roles
.venv/bin/python tools/initial_setup.py --skip-tags
.venv/bin/python tools/initial_setup.py --skip-nse
.venv/bin/python tools/initial_setup.py --role-file webapp/security_roles/read_only.yaml
.venv/bin/python tools/initial_setup.py --nse-repo-dir /path/to/Plum-Rules-NSE
```

The default role file creates a `Read Only` role from `webapp/security_roles/read_only.yaml`.
The file is intentionally plain YAML so permissions can be maintained without editing Python code.

Imported NSE files are copied into the Flask upload folder and stored in the DB with their filename and SHA-256 hash.
If a script with the same filename already exists, it is updated only when the content hash changed.

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

### `index_meili.py`

Import dumped JSON documents into the configured output Meilisearch index.

The script reads `tools/config.yaml` and writes to `OUT_MEILI_URL` / `OUT_MEILI_API_KEY`. The target index name comes from `INDEX_NAME`, defaulting to `plum`.

```bash
.venv/bin/python tools/index_meili.py --input-dir tools/meili_dump
```

Batch size can be adjusted:

```bash
.venv/bin/python tools/index_meili.py --input-dir tools/meili_dump --batch-size 500
```

Use `--progress` when you want percentage output:

```bash
.venv/bin/python tools/index_meili.py --input-dir tools/meili_dump --progress
```

This counts importable JSON documents before sending anything to Meilisearch. On large dumps this makes startup slower.

### `index_kvrocks.py`

Build or rebuild the Kvrocks search indexes from Meilisearch documents.
Kvrocks stores compact reverse indexes used by structured search; Meilisearch remains the source for full scan documents.

#### Use cases

Use an incremental import from an existing dump when you already have `tools/meili_dump/` and only want to index those files:

```bash
.venv/bin/python tools/index_kvrocks.py --input-dir tools/meili_dump
```

This does not delete the full Kvrocks index first. Existing documents keep their stored timestamps. Reindexed UIDs are refreshed and their old per-field values are removed before new values are written. Documents that are not present in the input dump remain in Kvrocks.

Use a rebuild from a dump when you want to clean stale Kvrocks keys but prefer to work from an offline Meilisearch export:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild --input-dir tools/meili_dump
```

This deletes known Plum Kvrocks keys, then imports every JSON document from the dump. Before deleting `doc:*`, it snapshots existing `first_seen` and `last_seen` values in memory and applies them during reimport.

Use a rebuild directly from Meilisearch when you want the cleanest operational path and do not need an intermediate dump directory:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili
```

This reads Meilisearch directly, verifies that Meilisearch returns at least one document, then deletes and rebuilds the known Kvrocks keys. It has the same timestamp preservation behavior as `--rebuild`, but avoids creating or relying on `tools/meili_dump/`.

Use `--retag` with either rebuild mode when tag rules must be recomputed during the rebuild:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili --retag
```

Without `--retag`, rebuilds preserve existing `tag:*` and `tags:*` indexes and do not parse active Tag Rules. With `--retag`, the script cleans existing tag indexes and recomputes tags from all active Tag Rules while parsing source documents.

#### Timestamp preservation

Search time bounds (`from` / `to`) are evaluated from Kvrocks only. They depend on `doc:{uid}.first_seen`, `doc:{uid}.last_seen`, `first_seen_index`, and `last_seen_index`; Meilisearch is not used as the live source for those time filters.

`last_seen` can usually be recovered from the scan document end time in Meilisearch. `first_seen` is historical state accumulated in Kvrocks and cannot always be reconstructed from Meilisearch alone.

Without `--rebuild`, existing `doc:{uid}` timestamps are kept for UIDs already present in Kvrocks. New UIDs get timestamps from the parsed scan document.

With `--rebuild` or `--rebuild-from-meili`, the script snapshots existing `doc:{uid}` timestamps before deleting keys. During reimport, it preserves:

- earliest known `first_seen`
- latest known `last_seen`

This protects timestamps for documents that are present in the rebuild source. If a document exists only in Kvrocks and is missing from the dump or Meilisearch source, it will not be recreated after a rebuild.

For extra safety before a full clean rebuild, export `first_seen` to CSV, rebuild, then import the CSV:

```bash
.venv/bin/python tools/first_seen_csv.py --export first_seen.csv
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili
.venv/bin/python tools/first_seen_csv.py --import first_seen.csv
.venv/bin/python tools/dump_object.py http_title
```

The CSV restore updates `doc:{uid}.first_seen` and `first_seen_index`. It does not overwrite `last_seen`.

#### Progress and tuning

Progress lines include total document count and percentage when available:

```text
Processed 18000/123456 Meili documents (14.6%); indexed=17500/123456 (14.2%); pending_batch=500
Indexed 20000/123456 (16.2%) documents
```

For `--rebuild-from-meili`, the total comes from Meilisearch. For `--input-dir`, the total is the number of JSON files in the dump directory.

Batch size can be adjusted:

```bash
.venv/bin/python tools/index_kvrocks.py --batch-size 500
```

Document parsing uses multiprocessing by default with one fewer worker than the CPU count. Set `--workers 1` to disable multiprocessing:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili --workers 1
```

Kvrocks writes stay in the main process. Worker processes only parse documents.

Ctrl+C is handled gracefully. The first Ctrl+C asks the tool to stop after flushing the already parsed pending batch and exits with status `130`. Press Ctrl+C a second time to force an immediate stop.

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
