# Migration guides

Latest published release: **Plum Island - 20 Years Hack.lu Release - v0.2610.0**
(released on 2026-10-14). The upgrade to current `main` covers Unreleased changes.

Choose the guide matching the **installed source version**, not the version you
want to install. The guides from older versions to v0.2610.0 are alternative
entry points. To continue to current `main`, follow the v0.2610.0-to-main guide
after completing the applicable release migration.

| Installed version | Destination | Guide | Main data work |
| --- | --- | --- | --- |
| `v0.2610.0` | Current `main` (Unreleased) | [Upgrade from v0.2610.0](migration-v0.2610.0-to-main.md) | One observed-tag catalogue backfill and security-role synchronization; no SQL migration or full index rebuild. |
| `v0.2604.0` | `v0.2610.0` | [Migration from v0.2604.0](migration-v0.2604.0-to-v0.2610.0.md) | SQL migrations 14–24, legacy IP-to-port conversion, certificate query/index migration. |
| `v0.2606.0` | `v0.2610.0` | [Migration from v0.2606.0](migration-v0.2606.0-to-v0.2610.0.md) | SQL migrations 17–24, per-port smarthash deduplication with merged history, certificate query/index migration. No IP-to-port split. |

## Before upgrading

- Follow the chosen guide's service and writer requirements; the older release
  migrations require stopping the web application, scheduler, agents and index writers.
- Take restorable backups of SQLite, Meilisearch, Kvrocks, configuration and raw
  scan data. Backups are operator-managed, not created by SQL migration scripts.
- Test on disposable copies. Meilisearch replacement and Kvrocks rebuilding are
  not a single transaction.
- The guides targeting v0.2610.0 use that published tag and its pinned submodule.
  The guide targeting `main` uses a moving revision; record the deployed commit.
- If the installation already includes some changes from `main`, inspect its
  actual schema and index format before choosing steps; do not blindly replay
  all migrations. Installations older than `v0.2604.0` are not covered here.
- Update scanner dependencies as directed before resuming work.

See the [release notes](../release_note.md) for user-facing changes and the
[certificate CN/DN guide](../migration_full_cert.md) for the shared query/index
compatibility change. Follow that procedure at the point indicated by the
version-specific guide, not as an independent second full reimport.
