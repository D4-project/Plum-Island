# Upgrade from `v0.2606.0` to current `main`

## Overview

This procedure starts from the [Plum Island `v0.2606.0` release](https://github.com/D4-project/Plum-Island/releases/tag/v0.2606.0) and targets `main` as documented on 2026-10-08 (base commit `7ed78fa`, plus the migration CLI change accompanying this guide). `main` is not a versioned release; check the commit being deployed and review later migrations if it has moved beyond this guide.

`v0.2606.0` already stores scan results per port. Do **not** run the IP-to-port split from the older [`v0.2604.0` guide](migration.md). This upgrade has two independent data changes:

1. Apply SQLite migrations `17` through `24` to application metadata, in order. Migration `23` can use retained Kvrocks history to backfill target creation dates.
2. Rehash the complete Meilisearch result set with the corrected `nmap2json` library. The migration reads each old document's `first_seen` and `last_seen` from source (`IN`) Kvrocks, falls back to JSON scan times for absent bounds, recomputes port hashes and IDs, merges date-only duplicates, and writes new JSON plus consolidated `.time` files. Reimport replaces the configured destination (`OUT`) Meilisearch index and rebuilds destination Kvrocks with the new IDs and dates.

Preparing the rehashed dump does not change either database. `--dry-run` writes no dump. The explicit reimport step replaces `OUT`; it does not change `IN` unless the `IN_*` and `OUT_*` settings point to the same services. Meilisearch replacement and Kvrocks rebuild are **not one transaction**.

This procedure assumes an existing `v0.2606.0` installation, its SQLite database, a complete Meilisearch index, and access to source Kvrocks. Missing historical bounds cannot be reconstructed from Meilisearch JSON: its scan times supply a fallback, which can shorten the recorded observation interval. It does not recover documents present only in Kvrocks or coordinate running scanners. Backups, service control, and destination selection belong to the operator.

## Procedure

### 1. Stop writers and preserve the source

Stop the web application, scheduler, and agents. Keep scan result ingestion and indexing paused through export and replacement so the Meilisearch dump and Kvrocks history refer to the same source state. Record the source Git revision and document count.

Take restorable backups of the SQLite database (including any WAL state), Meilisearch, Kvrocks, application configuration, and retained raw scan JSON. Keep a copy of `tools/config.yaml` outside the checkout. Test this procedure on disposable copies before using production destinations.

### 2. Update code and dependencies

From the Plum-Island repository root, update to the intended `main` commit and its tag-rule submodule. Preserve local configuration and changes before pulling; `git pull --ff-only` refuses a divergent branch.

```bash
git fetch origin
git checkout main
git pull --ff-only
git submodule sync --recursive
git submodule update --init --recursive
.venv/bin/python -m pip install -r requirements.txt
git rev-parse HEAD
```

The installed `nmap2json` must contain volatile-date normalization (`2610.1` satisfies the current `nmap2json>=2610.01` requirement). `migrate_smarthash.py` checks the installed library's SMTP, HTTP, and RTSP date behavior before processing data; a separate source checkout does not update the installed package. Update scanner environments to the same corrected hashing version before resuming them.

### 3. Configure source and destination

Review `tools/config.yaml` without replacing an existing installation's file. The export reads `IN_MEILI_URL`, `IN_MEILI_API_KEY`, and `INDEX_NAME`. Rehashing reads `IN_KVROCKS_HOST`, `IN_KVROCKS_PORT`, and optional `IN_KVROCKS_PASSWORD`. The importer reads `OUT_MEILI_*`, `OUT_KVROCKS_HOST`, `OUT_KVROCKS_PORT`, and `INDEX_NAME`.

For a disposable round trip, set `OUT_*` to disposable services; retain `IN_*` on the source. An in-place production migration may use the same services for `IN` and `OUT`, but the import then replaces the source index and Kvrocks keys. Review the printed OUT targets before confirming any replacement.

### 4. Apply SQLite migrations

Scripts `17`–`22` target `webapp/app.db`. Run them in order with all application writers stopped. Migration `18` adds Kong headers to the collected-header table; it is present after `v0.2606.0` and must not be skipped.

```bash
.venv/bin/python webapp/sql_upd/17_migrate_from_d7c3198bc3b3a7d6cf0ae39860fd1cfb58c1a4e3.py
.venv/bin/python webapp/sql_upd/18_migrate_from_89b4c246af69e340fa8ac66290c936506b23a638.py
.venv/bin/python webapp/sql_upd/19_migrate_from_b3b36001115d22b839ce630562bbf83ed0f166c0.py
.venv/bin/python webapp/sql_upd/20_migrate_from_1a77f9638812f6d238b5a7f26aace1f45ae06e2e.py
.venv/bin/python webapp/sql_upd/21_migrate_from_c1ef29af4ac597787b67d99982f9baade1817222.py
.venv/bin/python webapp/sql_upd/22_migrate_from_e1e711f41e9239b02bdba58dc4a9a5588d89619e.py
```

Migration `23` adds target insertion timestamps and shared network metadata. It uses surviving SQL scan history; an optional CSV from source Kvrocks can supply older `first_seen` values. Export that CSV **before** changing source Kvrocks if historical target dates matter:

```bash
.venv/bin/python tools/first_seen_csv.py --export /path/to/target-history.csv
.venv/bin/python webapp/sql_upd/23_migrate_from_4eb42ebc9bf251ffc5a563554967d1450d678df2.py --db webapp/app.db --history-csv /path/to/target-history.csv --dry-run
.venv/bin/python webapp/sql_upd/23_migrate_from_4eb42ebc9bf251ffc5a563554967d1450d678df2.py --db webapp/app.db --history-csv /path/to/target-history.csv
```

`first_seen_csv.py` reads `IN_KVROCKS_*` from `tools/config.yaml`; its current connection code does not pass `IN_KVROCKS_PASSWORD`, so verify source access before relying on this command. If no CSV is available, omit `--history-csv` from **both** migration `23` commands and review the dry-run's `fallback_now` count. Purged history cannot be recovered. See [migration 23 details](migration.md#target-network-metadata-migration-23) for how IP/CIDR and FQDN history is matched.

Migration `24` classifies stored targets as IP/CIDR or FQDN. Its dry-run reports invalid values without changing the database; resolve any reported IDs before applying it:

```bash
.venv/bin/python webapp/sql_upd/24_migrate_from_610859bfc6d1d92ed54d48bceab1565753043742.py --db webapp/app.db --dry-run
.venv/bin/python webapp/sql_upd/24_migrate_from_610859bfc6d1d92ed54d48bceab1565753043742.py --db webapp/app.db
```

Then refresh seed roles, header collection, rules, ports, and NSE scripts:

```bash
.venv/bin/python tools/initial_setup.py
```

### 5. Export the complete Meilisearch index

`dump_meilidb.py` reads `config.yaml` from its current directory and writes one JSON file per document under `meili_dump/`. Start with a nonexistent `tools/meili_dump/`; the script does not remove stale files. Do not run the export while indexing continues.

```bash
cd tools
../.venv/bin/python dump_meilidb.py --do-export
cd ..
find tools/meili_dump -type f -name '*.json' | wc -l
```

Wait for `Total documents exported` and compare it with the source Meilisearch index count. Investigate any mismatch before proceeding. This dump contains no Kvrocks `.time` companions; the next step reads source Kvrocks directly.

### 6. Validate and prepare the rehashed dump

Both commands require a new `tools/meili_dump_rehashed` path that does **not** already exist. The dry-run reads IN Kvrocks and reports source, port, unique, and merged counts without creating output. The second command writes one JSON and one `.time` file per new ID, plus `uid-map.jsonl` and a `migration.manifest` marker written last. For large data sets, place temporary SQLite work files on a disk with enough free space using `--work-dir /path/to/scratch-parent`.

Smarthash calculation uses `--workers` processes (default: logical CPU count minus one, minimum one). Use `--workers 1` for serial execution. Kvrocks reads and SQLite merging stay in the parent process; worker submissions are bounded in memory.

```bash
.venv/bin/python tools/migrate_smarthash.py \
  --input-dir tools/meili_dump \
  --output-dir tools/meili_dump_rehashed \
  --dry-run

.venv/bin/python tools/migrate_smarthash.py \
  --input-dir tools/meili_dump \
  --output-dir tools/meili_dump_rehashed
```

The merge keeps the minimum available `first_seen` and maximum available `last_seen`. If Kvrocks lacks a bound, JSON `body.starttime` or `body.endtime` supplies it; the summary reports `history_fallback_documents` and prints a warning. The retained report payload is the newest by `body.endtime`, falling back to source `last_seen`; ties are deterministic. Meaningful content differences remain separate. Check the reported counts, inspect sample `uid-map.jsonl` entries and `.time` files, and verify `migration.manifest` says `complete`. Do not import a partial output directory; restart preparation with a fresh path after a failure.

### 7. Test and replace OUT

First run a complete reimport against disposable OUT Meilisearch and Kvrocks. Confirm document counts, merged dates, new IDs, and absence of stale old IDs there. Then point `OUT_*` to the intended production destination, verify backups and stopped writers again, and run the same command:

```bash
.venv/bin/python tools/reimport_port_dump.py \
  --input-dir tools/meili_dump_rehashed \
  --meili-replace-mode swap \
  --areyousure_yes
```

The importer loads a temporary Meilisearch index, swaps it into `INDEX_NAME` after a complete import, and removes the previous index. It then clears known Plum Kvrocks indexes and all `doc:*` keys in OUT, reparses the prepared documents, and rebuilds keys under the new IDs using the `.time` companions. IN remains untouched when it is separate from OUT. External references to old IDs outside these two backends are not rewritten.

Meilisearch swap and Kvrocks rebuild are not atomic. If Kvrocks rebuild fails after the swap, keep ingestion stopped and retry from the **same complete prepared dump** after investigating the error. Do not use an incremental import: it leaves old IDs behind.

### 8. Verify and resume

Compare OUT Meilisearch document count with `unique_documents` in `migration.manifest`. Compare OUT Kvrocks `doc:*` count and `all_uids` with that count. For sample merged IDs from `uid-map.jsonl`, compare `doc:<new-id>.first_seen` and `.last_seen` with the prepared `.time` file; confirm old IDs no longer exist in OUT. Check representative search, IP detail, and tag results. Confirm the web app and scheduler start without schema errors.

Only after those checks, restart agents using the corrected hashing version and resume ingestion. If validation fails, stop writers and restore the matching SQLite, Meilisearch, and Kvrocks backups; restoring one backend alone may leave IDs inconsistent.

For tool options and backend behavior, see [Tools: date-only duplicate migration](tools.md#date-only-duplicate-migration) and the [smarthash TODO](../tools/TODO-smarthash.md). The full disposable round trip and a real production recovery remain unverified in that TODO; this guide describes the intended sequence, not a completed production run.
