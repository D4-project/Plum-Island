# Upgrade from `v0.2610.0` to current `main` (Unreleased)

This guide starts from an installation already upgraded to **v0.2610.0** and
targets the changes currently listed under [Unreleased](../release_note.md).
`main` is a moving destination, not a new published release. Record the deployed
Git revision when applying this procedure. For an older installation, first
complete the appropriate [versioned migration](migration.md).

## What changes

- Search helper columns display tags actually present in indexed documents.
  Existing indexes need one catalogue backfill; new ingestion and retagging
  maintain it automatically.
- Discovery API v1 adds protected read operations for the separate
  [Plum-Virion MCP server](https://github.com/D4-project/Plum-Virion).
  Synchronize framework roles after deploying the API.
- Structured queries support one level of parentheses. Candidate planning uses
  existing Kvrocks cardinalities; no new counters or rebuild are needed.
- Resolved CSV export includes last scan dates, stored PTR names and Passive DNS
  records filtered to the search period.
- Meilisearch dump imports support confirmed-batch checkpoints and `--continue`.
- Root logging uses configured `LOG_LEVEL`, with `WARNING` as the missing/invalid
  fallback instead of `DEBUG`. Existing explicit settings remain effective.
- View registration removes obsolete permission/view pairs from all referencing
  roles before FAB synchronization, fixing repeated startup cleanup warnings
  with Flask-AppBuilder 4.8.1 (#260).

### Unique scan profile names

`./updisland.sh` applies migration 25 to the configured SQLite database before
role synchronization. It also catches up migration 24 on an installation with the
migration 23 schema. If migration 25 was already applied manually, the updater
checks the existing unique index and records the migration.

The updater prints the backup path and the final migration number. If names
collide, it lists the profile IDs grouped by duplicate name and rolls back the
pending batch. Give those profiles distinct names and rerun the updater.

### Unique protocol/port pairs

`./updisland.sh` applies SQLite migration 26 automatically. For each duplicate
protocol/port pair it keeps the lowest port ID and its description. It prints the
discarded IDs and any conflicting descriptions, and reconnects every affected
scan profile to the surviving ID. TCP/80 and UDP/80 remain separate entries.
Queued jobs keep their saved port lists.

The Ports form and `POST` / `PUT` under `/api/v1/ports/` reject duplicate pairs.
API clients storing port IDs can refresh them from `GET /api/v1/ports/` or
the `port_ids` field returned by `GET /api/v1/scanprofiles/<id>`.

If the migration fails, the updater rolls back the transaction. To undo a
completed merge, stop Plum and all SQLite writers, restore the backup printed by
the updater with SQLite's `.restore` command, and redeploy the preceding code
before restarting. Restoring returns the whole database to the backup timestamp.

## 1. Deploy code and synchronize roles

Use the normal controller service stop/restart procedure during code replacement.
Preserve local configuration and follow the operator-managed backup policy.
From the Plum-Island repository root:

```bash
git fetch origin
git switch main
git pull --ff-only origin main
git submodule sync --recursive
git submodule update --init --recursive
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/update_sql.py
.venv/bin/python tools/initial_setup.py --roles-only
git rev-parse HEAD
```

These commands use the tag-rule submodule revision pinned by the selected main
commit. `updisland.sh` fetches the latest remote tag rules, runs the same SQLite
updater and synchronizes roles. Install dependency changes and run the catalogue
backfill below separately. Keep existing configuration files in place.

The Read Only role gains the six `DiscoveryApi` method permissions. Custom roles
require explicit grants for the operations they need; see the
[Discovery API contract](discovery.md#authentication-and-installation).
Existing search route permissions continue to cover the helper catalogue.

### Obsolete FAB permissions

Before deploying this cleanup to an existing installation, stop the controller
and its workers and back up the configured SQL database, including role grants.
For SQLite, use its backup operation rather than copying a live database without
its WAL files. Substitute the configured database and backup paths:

```bash
sqlite3 /path/to/app.db ".backup '/path/to/backups/app-before-permission-cleanup.db'"
```

Restarting with the updated code, or running the role synchronization command
above, triggers cleanup while each view registers. Permissions absent from that
view's registered permission list are detached from every referencing role and
their permission/view pairs are deleted in one transaction per view. The known
obsolete entries are `TargetsView.custom_action` and `can_add`, `can_download`,
`can_delete`, and `can_edit` on `TargetScanStatesView`. Current permissions,
registered custom actions, and shared permission/view-name records are retained.
No SQL schema migration, manual permission deletion or scan-index rebuild is
required. Repeated startups make no further cleanup changes.

If cleanup fails, its transaction is rolled back and startup/role synchronization
raises `Failed to clean obsolete permissions for view ...`; investigate the SQL
database error before retrying. Earlier successfully registered views may already
have completed their own cleanup. Verify that startup no longer emits the five
`Refused to delete permission view, assoc with role exists` warnings and that
Admin, Read Only and custom roles retain their intended access.

To recover the exact pre-upgrade role assignments, stop all controller processes,
restore the SQL backup through the normal database restore procedure, and deploy
the previous code before restarting. Restoring the database also restores other
application state to the backup time; preserve any subsequent state before doing
so. Returning to previous code alone does not recreate deleted role grants.

## 2. Initialize the observed-tag catalogue once

Verify that `OUT_KVROCKS_HOST` and `OUT_KVROCKS_PORT` in `tools/config.yaml` point
to the same Kvrocks instance used by the deployed controller's `KVROCKS_HOST`
and `KVROCKS_PORT`. Then run:

```bash
.venv/bin/python tools/backfill_tag_catalogue.py
```

For another tool configuration or batch size:

```bash
.venv/bin/python tools/backfill_tag_catalogue.py --config /path/to/tools.yaml --batch-size 500
```

The tool performs one maintenance keyspace scan with `MATCH tag:*`, checks
reverse-index cardinalities in batches and adds tag names to `tag_catalogue`.
It never loads document UID memberships, reads SQL tag rules or reparses reports.
It prints its destination and progress. No index replacement or full reindex is
required. Repeating it is safe; it only adds candidates and can run during normal
ingestion. Avoid running it concurrently with a destructive tag flush/rebuild.

Without this step, the new table contains only tags encountered by writes since
the update. The web cache lasts 60 seconds per worker; reload after expiry to see
the initialized catalogue. The five columns remain Proto, Type, Products,
Vendors and Vulns. They show globally indexed tags, independent of query/dates.
Zero-count candidates are hidden. Full tag flush/rebuild clears the catalogue;
rebuilds preserving tags preserve it. See [Kvrocks objects](kvrocks_objects.md#tag-specific-updates).

## 3. Optional: install Plum-Virion

On the machine running Codex, follow the
[Virion installation guide](https://github.com/D4-project/Plum-Virion/blob/main/documentation/usage.md).
Use a dedicated Plum account and a private `config.yaml`. `--check` verifies
controller access; registration requires `bash install.sh --codex` or manual
`codex mcp add`. Confirm with `codex mcp list`, restart Codex, then open `/mcp`.
No MCP installation is needed for normal browser search.

Discovery API tag discovery intentionally lists active rule tags. It differs
from the search helper table's observed-tag catalogue; see [Discovery](discovery.md).

## Logging configuration

Review `LOG_LEVEL` in the existing `webapp/config.py`. New sample configurations
default to `WARNING`; an existing `LOG_LEVEL = "DEBUG"` is preserved and still
enables debug output. Set it explicitly to `INFO` or `WARNING` for lower log
volume, then restart the controller. It applies to root/console logging even
when `LOG_ENABLED = False`; that flag only enables persistent files. Supported
names are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Missing or invalid
values fall back to `WARNING`. No database or index migration is involved.

## Existing workflows

Existing flat queries remain valid. Parentheses are optional and limited to one
grouping level; no stored report queries need automatic conversion. See
[search syntax](search.md). Resolved CSV uses the existing Passive DNS settings;
PTR names come from stored scan reports, without live reverse-DNS queries.

Dump imports automatically write a checkpoint after each confirmed batch. Resume
with `tools/index_meili.py --continue` only when that checkpoint exists and the
dump/destination match. An import interrupted before checkpoint support was
installed cannot be resumed precisely. See [import tools](tools.md#index_meilipy).

## Rollback

The catalogue is additive; older code ignores its key. No SQL schema or scan-data
rollback is required for this upgrade. Restore the previous code/dependencies
through the normal deployment procedure. Before returning to an older query
parser, rewrite any newly grouped stored report/rule queries into its supported
flat syntax. Stop/remove Virion registration and revoke its dedicated Discovery
permissions if rolling back the controller API.


## Automatic indexing (#271)

Read [automatic indexing](automatic-indexing.md) before rollout. This migration
adds managed Kvrocks generations/control metadata, not SQL tables. The scheduler
bootstraps historical coverage in a separate generation and supervises the child
process. Verify capacity and COPY support, retire legacy writers, and retain
sources/history for recovery. The GUI now displays progress without reindex
buttons. Validate latency and ingestion lag on representative staging data.
