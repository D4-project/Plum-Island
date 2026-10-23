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

There are **no new SQL schema migrations** after the scripts already included
in v0.2610.0 for these changes. Do not replay SQL migrations 14–24, the
IP-to-port conversion, smarthash migration or certificate rebuild as part of
this upgrade. Existing scan documents, UIDs and observation history are retained.

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
.venv/bin/python tools/initial_setup.py --roles-only
git rev-parse HEAD
```

These commands use the tag-rule submodule revision pinned by the selected main
commit. `updisland.sh` is an alternative update path that also fetches the latest
remote tag rules and synchronizes roles; it does not install dependencies or run
the catalogue backfill below. Keep existing configuration files in place.

The Read Only role gains the six `DiscoveryApi` method permissions. Custom roles
require explicit grants for the operations they need; see the
[Discovery API contract](discovery.md#authentication-and-installation).
Existing search route permissions continue to cover the helper catalogue.

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
