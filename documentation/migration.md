# Migration from `v0.2604.0` to current `main`

This guide upgrades a `v0.2604.0` Plum Island instance to current `main`.

Stop the web application, scheduler, and agents before starting. Do not run scans while migrating.

## 1. Back up data

Back up SQLite first:

```bash
cp webapp/app.db "webapp/app.db.backup.$(date +%Y%m%d-%H%M%S)"
cp webapp/app.db-wal "webapp/app.db-wal.backup.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
cp webapp/app.db-shm "webapp/app.db-shm.backup.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
```

Also back up external indexes before destructive reimport:

- Meilisearch data directory or snapshot
- Kvrocks/RocksDB data directory or snapshot
- `tools/config.yaml`
- `webapp/config.py`

If possible, test the full procedure on a copy of production first.

## 2. Update code and dependencies

```bash
git fetch origin
git checkout main
git pull --ff-only
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## 3. Apply SQL migrations

`v0.2604.0` already contains migrations `01` to `13`.
From `v0.2604.0` to current `main`, apply only these SQL update scripts, in order:

```bash
.venv/bin/python webapp/sql_upd/14_migrate_from_fb0572514a77717f6d9ad6cd05db6768be82178a.py
.venv/bin/python webapp/sql_upd/15_migrate_from_173795d186ee69c8abca1ce75d5bb0ff749b55a0.py
.venv/bin/python webapp/sql_upd/16_migrate_from_28501acb1bc77d15ea1dc5f9c41684d40daecf10.py
.venv/bin/python webapp/sql_upd/17_migrate_from_d7c3198bc3b3a7d6cf0ae39860fd1cfb58c1a4e3.py
```

What they do:

- `14`: add scan profile cycle tracking tables/columns
- `15`: add default HTTP header collection config
- `16`: add scan-unit counters for scan profile progress
- `17`: add the narrow `Feeder` API role for target import tools

Do not rerun older migrations unless migrating from a version older than `v0.2604.0`.

## 4. Refresh seed data

Run the initial setup loader to ensure current roles, TCP ports, header collection, tag rules, NSE scripts, and the default banner scan profile exist:

```bash
.venv/bin/python tools/initial_setup.py
```

This imports current YAML tag rules from `webapp/tags/`, clones/updates `https://github.com/D4-project/Plum-Rules-NSE`, imports NSE scripts, and creates the all-target `Default banner scan` profile for ports `22`, `80`, and `443` with `banner.nse`.

## 5. Configure tool migration targets

Prepare `tools/config.yaml`:

```bash
cp tools/config.yaml.sample tools/config.yaml
```

Edit at least:

```yaml
IN_MEILI_URL: "http://old-or-current-meili:7700"
IN_MEILI_API_KEY: "..."
OUT_MEILI_URL: "http://target-meili:7700"
OUT_MEILI_API_KEY: "..."
INDEX_NAME: "plum"

IN_KVROCKS_HOST: "old-or-current-kvrocks"
IN_KVROCKS_PORT: 6666
OUT_KVROCKS_HOST: "target-kvrocks"
OUT_KVROCKS_PORT: 6666
```

For an in-place migration, `IN_*` and `OUT_*` usually point to the same services.

## 6. Migrate IP documents to port documents

Current `main` stores one Meilisearch document per IP/port observation instead of one IP document containing all ports.

### 6.1 Dump current IP-scoped Meilisearch documents

Run from `tools/` because this script reads `config.yaml` from the current directory:

```bash
cd tools
../.venv/bin/python dump_meilidb.py
cd ..
```

Output:

```text
tools/meili_dump/
```

### 6.2 Split dump into port-scoped documents

```bash
.venv/bin/python tools/split_meili_dump_by_port.py \
  --input-dir tools/meili_dump \
  --output-dir tools/meili_dump_port
```

This creates:

```text
tools/meili_dump_port/
```

It also writes `.time` companion files from `IN_KVROCKS_*` when possible, preserving old `first_seen` / `last_seen` timestamps.

### 6.3 Reimport port-scoped dump

Warning: this is destructive for `OUT_MEILI_*` and `OUT_KVROCKS_*`.

```bash
.venv/bin/python tools/reimport_port_dump.py \
  --input-dir tools/meili_dump_port \
  --areyousure_yes
```

Default behavior:

- import port-scoped documents into a temporary Meilisearch index
- atomically swap it into `INDEX_NAME`
- rebuild OUT Kvrocks from the port-scoped documents
- recompute tags from active DB tag rules
- restore timestamps from `.time` companion files

Useful options:

```bash
# slower, simpler parsing path
.venv/bin/python tools/reimport_port_dump.py --input-dir tools/meili_dump_port --workers 1 --areyousure_yes

# only rebuild Kvrocks from already imported port documents
.venv/bin/python tools/reimport_port_dump.py --input-dir tools/meili_dump_port --skip-meili --areyousure_yes

# only replace Meilisearch, skip Kvrocks rebuild
.venv/bin/python tools/reimport_port_dump.py --input-dir tools/meili_dump_port --skip-kvrocks --areyousure_yes
```

## 7. Validate

Start Plum Island again, then check:

- web UI starts without DB errors
- `Config -> Scan Profiles` contains `Default banner scan`
- `Config -> Header Collection` contains default HTTP headers
- `Config -> Tag Rules` contains imported rules
- `Config -> Nse Scripts` contains imported NSE scripts
- structured search works for `port:443`
- structured search works for `http_header:content-type`
- structured search works for `tag:proto:ssh` when matching data exists
- IP detail page still opens for known scanned IPs

If validation fails, stop services and restore the SQLite, Meilisearch, and Kvrocks backups before retrying.
