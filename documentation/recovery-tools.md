# Search Index Recovery

Plum Island stores full scan documents in Meilisearch and structured search
indexes in Kvrocks. The two backends must reference the same document UIDs.

Use this page for two different recovery operations:

| Problem | Procedure |
| --- | --- |
| Kvrocks references UIDs missing from Meilisearch | Recover documents from retained raw job JSON with `reintegrate_missing_meili.py` |
| Kvrocks fields, keys, or tags must be regenerated from authoritative Meilisearch documents | Rebuild Kvrocks with `index_kvrocks.py --rebuild-from-meili` |

Run missing-document recovery before a Kvrocks rebuild. A rebuild uses
Meilisearch as its source, so a document that still exists only in Kvrocks cannot
be reconstructed by that operation.

## Production preparation

Run tools from the repository root with the project virtual environment.

For a consistent production snapshot, stop the web application before the final
recovery or rebuild. This stops scheduler writes to Meilisearch and Kvrocks while
the tools compare or replace index state. Back up these assets first:

- `webapp/config.py`
- retained raw scan files under `JSON_FOLDER`
- Meilisearch data or snapshot
- Kvrocks/RocksDB data or snapshot
- SQLite application database

The dry run for missing Meilisearch documents is read-only against both search
backends. The Kvrocks rebuild is destructive to known Plum search-index keys.

## Recover Kvrocks-only documents into Meilisearch

### What the tool does

`tools/reintegrate_missing_meili.py`:

1. streams all UIDs from `all_uids` in Kvrocks into a disk-backed SQLite work DB;
2. streams Meilisearch document IDs and removes present UIDs from candidates;
3. reads retained raw job JSON files once;
4. regenerates current port-scoped UUIDs with the same hashing logic as the scheduler;
5. keeps the newest matching raw observation for every missing UID;
6. writes a CSV report;
7. with `--apply`, adds recoverable documents to Meilisearch in confirmed batches.

It never deletes or rebuilds Kvrocks. Every Meilisearch write task must finish
with status `succeeded`; failure or timeout aborts the run. Apply mode prints the
task UID immediately, then its `enqueued` or `processing` status every 30 seconds.
The default per-task timeout is 15 minutes.

### Configuration

By default, the tool reads these settings directly from `webapp/config.py`:

- `MEILI_DATABASE_URI`
- `MEILI_KEY`
- `KVROCKS_HOST`
- `KVROCKS_PORT`
- `JSON_FOLDER`

Use another bare-install config or raw JSON directory when required:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --config /srv/plum/webapp/config.py \
  --json-folder /srv/plum/webapp/app/jsons
```

The SQLite work DB is temporary by default. Large installations need enough free
space under the system temporary directory to hold the UID comparison. Put it on
a larger filesystem when needed; the target path must not already exist. An
explicit work DB is recommended for production recovery:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --apply \
  --work-db /srv/plum-recovery/missing-uids.sqlite
```

Each submitted Meilisearch task UID is committed to this work DB before the tool
waits for completion. On timeout, connection error, or interruption, the work DB
is preserved. A Meilisearch client timeout does not cancel the server-side task.
Do not start a fresh recovery while that task remains queued or processing.

### Dry run

Stop the application when exact counts are required, then run:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --report /tmp/missing-meili-dry-run.csv
```

No Meilisearch or Kvrocks record is changed. Report statuses are:

- `recoverable`: matching retained raw JSON document found;
- `unrecoverable`: Kvrocks metadata exists, but no matching retained raw document was found.

Each row includes UID, IP, first/last-seen metadata, selected source timestamp,
and source JSON path. Exit status is `2` when one or more UIDs are unrecoverable;
the CSV is still complete.

### Apply recovery

Review dry-run report and keep application stopped. Then run a fresh comparison
and reintegration:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --apply \
  --report /tmp/missing-meili-applied.csv
```

Tune batch size and task timeout for a busy or large Meilisearch instance:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --apply \
  --batch-size 500 \
  --task-timeout-ms 600000 \
  --report /tmp/missing-meili-applied.csv
```

Apply mode only adds or replaces documents identified as missing during that run.
Existing Meilisearch documents are not bulk rewritten. Re-running the tool is
safe: successfully restored UIDs are present during the next comparison and are
not selected again.

### Resume an interrupted apply

Use the work DB path printed by the failed or interrupted run:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --apply \
  --resume-work-db /srv/plum-recovery/missing-uids.sqlite \
  --report /tmp/missing-meili-applied.csv
```

Resume skips the Kvrocks/Meilisearch comparison and raw JSON scan. For every
persisted task UID, it queries the existing Meilisearch task and waits for it;
it does not submit the same batch again. Confirmed batches remain marked in the
work DB, then only remaining batches are submitted.

If the server task is blocked behind another operation, such as snapshot
creation, the output remains `status=enqueued`. Resolve or finish the earlier
Meilisearch task, then run the same resume command again.

### Validate recovery

Run another dry comparison:

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --report /tmp/missing-meili-validation.csv
```

Expected summary:

```text
missing=0
Summary: reintegrated=0; recoverable=0; unrecoverable=0; inserted=0
```

Also reopen an affected `/ip/<address>` page and confirm missing-document warnings
are gone.

If UIDs remain `unrecoverable`, restore older raw JSON backups and run the tool
again. A Kvrocks rebuild will remove their structured-search references because
Meilisearch has no source document for them.

## Rebuild Kvrocks from Meilisearch

### When to rebuild

Use a direct rebuild when Meilisearch contains the complete authoritative
document set but Kvrocks has stale, corrupt, or outdated parsed indexes. Common
cases include:

- parser/index field changes must apply to historical documents;
- stale Kvrocks reverse-index keys must be removed;
- HTTP header collection rules changed;
- tag rules must be recomputed for all documents;
- consistency validation still reports Kvrocks indexing problems after missing
  Meilisearch documents were recovered.

Do not use this operation to recover missing Meilisearch documents.

### Configure source and destination

`index_kvrocks.py` reads `tools/config.yaml`. Start from sample:

```bash
cp tools/config.yaml.sample tools/config.yaml
chmod 600 tools/config.yaml
```

For an in-place production rebuild, point Meilisearch input and Kvrocks output at
the live services. Point both Kvrocks input and output at the same instance when
using the timestamp backup helper:

```yaml
IN_MEILI_URL: "http://127.0.0.1:7700"
IN_MEILI_API_KEY: "replace-with-production-key"
INDEX_NAME: "plum"

IN_KVROCKS_HOST: "127.0.0.1"
IN_KVROCKS_PORT: 6666
OUT_KVROCKS_HOST: "127.0.0.1"
OUT_KVROCKS_PORT: 6666

ONLINETLD: false
TLDADD:
  - "local"
```

Keep `tools/config.yaml` outside commits. Verify endpoints and backup both
backends before continuing.

### Preserve first-seen history

`first_seen` is historical Kvrocks state and cannot always be reconstructed from
Meilisearch documents. Export it outside Kvrocks before the rebuild:

```bash
.venv/bin/python tools/first_seen_csv.py \
  --export /srv/plum-recovery/first-seen-before-rebuild.csv
```

`--rebuild-from-meili` preserves existing `doc:{uid}` timestamp hashes in place
and merges them while rebuilding. The CSV is an additional recovery copy if the
backend or rebuild must be restored manually.

### Run direct rebuild

With the application stopped:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili
```

Before deleting known Plum search keys, the tool fetches the first Meilisearch
page and refuses to continue when Meilisearch returns no documents. It then:

- clears `all_ips`, `all_uids`, timestamp sorted indexes, UID/IP mappings, and
  configured parsed-field reverse indexes;
- preserves `doc:{uid}` hashes so known timestamps can be merged;
- streams full documents from Meilisearch;
- reparses documents;
- writes Kvrocks in bounded batches.

The rebuild source is only Meilisearch. Kvrocks-only UIDs are not placed back in
`all_uids` or parsed search indexes.

### Recompute tags

Default rebuild preserves existing `tag:*` and `tags:*` keys. Use `--retag` for a
clean tag rebuild from active DB-backed Tag Rules:

```bash
.venv/bin/python tools/index_kvrocks.py \
  --rebuild-from-meili \
  --retag
```

`--retag` loads application config and active Tag Rules, deletes existing tag
indexes, and recomputes tags while parsing every Meilisearch document. Use this
mode when removing stale document references or after changing tag rules.

### Performance and interruption

Adjust write batch size:

```bash
.venv/bin/python tools/index_kvrocks.py \
  --rebuild-from-meili \
  --batch-size 500
```

Parsing uses CPU count minus one worker by default. Disable multiprocessing for
diagnostics or constrained hosts:

```bash
.venv/bin/python tools/index_kvrocks.py \
  --rebuild-from-meili \
  --workers 1
```

First `Ctrl+C` requests graceful stop and flushes the current pending parsed
batch; exit status is `130`. A second `Ctrl+C` forces immediate stop. A stopped
rebuild leaves Kvrocks incomplete and must be run again before restarting the
application.

### Validate rebuilt Kvrocks

Check summary ends with zero parse errors:

```text
Kvrocks indexing complete: processed=<count> indexed=<count> errors=0
```

Optionally validate timestamp CSV without writing:

```bash
.venv/bin/python tools/first_seen_csv.py \
  --import /srv/plum-recovery/first-seen-before-rebuild.csv \
  --dry-run
```

Inspect representative indexed values:

```bash
.venv/bin/python tools/dump_object.py http_title
```

Restart application, test structured searches, then inspect several `/ip/<address>`
pages. Run `reintegrate_missing_meili.py` once more: expected missing count is
zero.

## Recommended complete recovery order

1. Stop application.
2. Back up SQLite, raw JSON, Meilisearch, and Kvrocks.
3. Run missing-Meilisearch dry run.
4. Apply recoverable Meilisearch documents.
5. Repeat dry run and record any unrecoverable UIDs.
6. Export `first_seen` CSV.
7. Rebuild Kvrocks from Meilisearch, normally with `--retag` for clean consistency.
8. Validate counts, parse errors, timestamp CSV, structured search, and IP pages.
9. Restart application.
