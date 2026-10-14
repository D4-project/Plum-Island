# Migration guides

Target release: **Plum Island - 20 Years Hack.lu Release - v0.2610.0**
(released on 2026-10-14).

Choose the guide matching the **installed source version**, not the version you
want to install. The procedures below are alternative entry points, not two
guides to run consecutively.

| Installed version | Destination | Guide | Main data work |
| --- | --- | --- | --- |
| `v0.2604.0` | `v0.2610.0` | [Migration from v0.2604.0](migration-v0.2604.0-to-v0.2610.0.md) | SQL migrations 14–24, legacy IP-to-port conversion, certificate query/index migration. |
| `v0.2606.0` | `v0.2610.0` | [Migration from v0.2606.0](migration-v0.2606.0-to-v0.2610.0.md) | SQL migrations 17–24, per-port smarthash deduplication with merged history, certificate query/index migration. No IP-to-port split. |

## Before upgrading

- Stop the web application, scheduler, agents and other index writers.
- Take restorable backups of SQLite, Meilisearch, Kvrocks, configuration and raw
  scan data. Backups are operator-managed, not created by SQL migration scripts.
- Test on disposable copies. Meilisearch replacement and Kvrocks rebuilding are
  not a single transaction.
- The versioned guides use the published `v0.2610.0` tag and its pinned submodule.
- If the installation already includes some changes from `main`, inspect its
  actual schema and index format before choosing steps; do not blindly replay
  all migrations. Installations older than `v0.2604.0` are not covered here.
- Update scanner dependencies as directed before resuming work.

See the [release notes](../release_note.md) for user-facing changes and the
[certificate CN/DN guide](../migration_full_cert.md) for the shared query/index
compatibility change. Follow that procedure at the point indicated by the
version-specific guide, not as an independent second full reimport.
