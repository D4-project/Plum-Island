# Plum Settings

Administrators can open **Security → Plum Settings** to configure Plum's services
and background work. The configured Flask-AppBuilder administrator role is
required for both the menu and direct requests; assigning the view's permissions
to another role does not grant access.

The page displays 56 Plum settings from `webapp/config.py.template`.
Authentication, themes, Flask/FAB options and SQLAlchemy configuration remain in
`config.py`. Runtime clients and scheduler state are not editable.

Lookup cache lifetimes are configurable in hours: WHOIS **24**, Passive DNS **12**,
and combined IP/AS information **24**. See [cache internals](sysinternal/caching.md)
for shared consumers, expiry and refresh behavior.

**Enable Passive DNS** (`PDNS_ENABLED`) defaults to **False** in new installations.
It requires both `PASSIVE_USER` and `PASSIVE_PWD` before settings can be saved
with the switch on. `setup.sh` enables it only when the operator selects Passive
DNS and supplies both credentials. Existing installations without the switch
retain their previous credential-based behavior after upgrade; an explicit
`PDNS_ENABLED = False` always disables it. Restart Plum-Agent after changing it.
Disabled Passive DNS stays visible as a status on IP pages; reports and exports
omit PDNS data. If an enabled lookup fails, IP pages show a failure dialog and
reports/exports warn that PDNS data is incomplete.

Under **IP detail map**, **Show location map** (`MAP_ENABLED`, default **True**)
controls the Location card in the IP detail **Informations** tab. Restart
**Plum-Agent** after changing it. See [network requirements](network.md#browser-and-scanner-traffic)
for the browser’s tile requests.

## Cards and field help

Cards group connectivity to Meilisearch, Kvrocks, CIRCL services and SMTP;
scheduling; background indexing; storage and retention; search, reports and
domain parsing; and logging. Each field shows its purpose, unit, configuration
key, **Default: …**, and **Restart required: Plum-Agent**. Defaults remain visible
after saving a different value. Empty defaults say **Not set**; the insecure
example Meilisearch key is never offered as a usable default.

`SCAN_DELAY` is an inactive legacy setting: scan frequency belongs to scan
profiles. It is explained and read-only; the remaining 54 fields are editable.
The obsolete `LOG_ROTATION_DAYS` field is omitted: log files always rotate daily
at local midnight. **Log retention** controls how long old log files are kept.
**Log Meilisearch HTTP requests** under **Logging** is disabled by
default. Enable it with **Log level** set to **DEBUG** to trace requests from
automatic indexing. See [Automatic indexing](automatic-indexing.md#meilisearch-connections-and-http-tracing).
Older `ONLINETLD`/`TLDS` flags are retired and remain ignored, as described in
[Scanning](scanning.md); suffix extraction is offline, with `TLDADD` for additional
private suffixes. Those removed flags are not reintroduced as controls.

Secrets have **Keep unchanged**, **Replace credential**, and, where supported,
**Clear credential** actions. The page never sends an existing credential to the
browser. Blank password inputs do not erase stored credentials. A saved override
can be removed with **Use config.py value**; this takes effect after restart.

## Saving and applying changes

This release preserves startup-based configuration loading. **Save settings**
persists changes; it does not modify a running service, start a second worker,
restart a process, or reindex data. Fields whose saved values differ from the
current web process show **Pending restart** and the applied non-secret value.
Secret changes show pending status without either value.

Every page displays a persistent **Configuration changed. Restart Plum-Agent to
apply changes.** banner while saved settings differ from the loaded configuration.
It survives navigation and cannot be dismissed like a normal flash message. It
disappears after restart, or when pending edits are reverted to the applied values.
All roles see the reminder; it contains no configuration values or credentials.

Restart **Plum-Agent**, using your normal process manager. This includes the web
application and scheduler. In the shipped launcher, the scheduler runs inside the web
application and owns its indexing child; it is not a separate service. Restarting
only the indexing child is insufficient: it inherits its parent's already-applied
configuration. The UI compares against the web process handling the request;
with multiple web processes, restart all of them before considering deployment
complete. Newly started web processes may already show their new values while
older processes still require restart.

| Setting family | Why a restart is needed |
| --- | --- |
| Meilisearch and Kvrocks connectivity | Backend clients are constructed in the web/scheduler and indexing processes. Restart them together to avoid split backends. |
| Scheduling | Scheduler intervals and controller configuration are established at startup. |
| Background indexing | The worker copies batch/pacing settings at startup; the controller supplies the applied configuration snapshot. |
| SMTP, passive DNS, retention, reports and search | Consumers read the process configuration loaded at startup, even where a setting is used only on the next operation. |
| Domain suffixes | Changes affect parser semantics; after restart, automatic reconciliation can reparse affected captures. Existing frozen jobs retain their own inputs. |
| Logging | Log handlers are established at process startup, including indexing workers. |

Changing a directory does **not** move files. Migrate existing data before
restarting against a new location. Reducing retention makes older files eligible
for deletion by the next maintenance operation after restart. Changing only
operational settings does not change parser fingerprints or discard a frozen
reconciliation checkpoint.

## Storage and precedence

The shared registry and loader live in `webapp/plum_settings/` and do not require
Flask to be started. Configuration precedence is:

1. Existing `config.py` values and their existing consumer fallbacks.
2. Validated Plum overrides saved through the page.

Missing overrides preserve the existing installation behavior. Displayed template
defaults do not silently populate previously absent runtime settings on startup.
An absent setting is prefilled with its documented default, including numbers,
toggles, lists and paths. Saving an untouched prefilled field preserves its existing
runtime fallback; editing a field creates an explicit override. The default remains
visible below the field after editing. Credentials remain blank and masked.
Changing a value in `config.py` does not supersede a saved override: remove the
override through the page or use offline recovery first.

The default private directory is `webapp/.plum-settings/`, relative to the deployed
code, independent of the working directory. The **deployment environment** variable
`PLUM_SETTINGS_DIR` selects another directory; it cannot be changed through the
page. The directory must be owned by the service account with mode `0700`; files
must be owned by it with mode `0600`. Existing unsafe permissions are rejected.

Files include:

- `settings.json`: latest saved overrides and revision.
- `settings.previous.json`: overrides before the most recent successful change.
- `runtime-<id>.json`: immutable configurations pinned by application/worker processes.
- `applied.json`: snapshot last published by the scheduler owner, used by
  `tools/index_generation_admin.py`. Importing Flask in a helper process does not
  publish a different controller backend.
- `settings.lock`: stable lock for concurrent writers and startup reads.

Credentials are stored in these private files, including snapshots and backups;
they are not encrypted. Protect backups like `config.py`. Default local storage
is ignored by Git and excluded from the Docker build context. Concurrent saves
use revision checks and a file lock. Validated JSON is written to a flushed private
temporary file and atomically replaces the previous file. A stale form receives
a conflict and must be reloaded; invalid fields do not partially update settings.

Workers receive only a private snapshot identifier in their environment, never
credentials. A child spawned after a GUI save still reads its controller's
applied snapshot. An invalid/missing snapshot fails closed instead of selecting
pending settings. Manually invoking `tools/reconcile_index.py` also selects the
last controller snapshot and refuses pending overrides if no controller has
applied a configuration yet. Old snapshots are retained so live controllers can continue
launching children; remove obsolete snapshots only while all Plum processes are
stopped and after taking a protected backup. `tools/index_meili.py` retains its
separate `tools/config.yaml` configuration and is not changed by this page.

## Docker

The image and Compose configuration set `PLUM_SETTINGS_DIR=/plum/data/settings`,
inside the existing persistent data volume. No database migration is required.
The existing entrypoint continues generating `config.py` from environment on its
first launch. GUI overrides are loaded afterward and win over those generated
values. Container replacement retains GUI settings while the data volume is kept.
Environment variables are not an additional live configuration override layer.

For another deployment, mount a durable directory and set `PLUM_SETTINGS_DIR`
before starting Plum. Read-only application code is supported when this separate
directory is writable. Use the same path and service account for the controller,
indexing workers and administrative tools.

## Testing a different revision

Give a preview its own private `PLUM_SETTINGS_DIR` before the first start, even
when it uses the same `config.py` as the installed version. For example, run
`PLUM_SETTINGS_DIR="$HOME/.local/state/plum/preview" python run.py` from a separate
checkout’s `webapp` directory. With the variable unset, each checkout already
uses its own `webapp/.plum-settings` directory.

A version predating the location map rejects a saved `MAP_ENABLED` override.
If you shared a settings directory, select **Use config.py value** for **Show
location map** and save from the newer version before rolling back, or restore
the matching backup as described below. Compare other edits made since the
backup, including scheduler settings. When upgrading from an early map preview,
Plum reads the map switch and ignores its retired tile URL and attribution.

## Offline recovery and rollback

If a saved backend or directory prevents startup:

1. Stop all Plum web/controller/indexing processes with the normal process manager.
2. Back up the **whole private settings directory**, retaining owner-only permissions.
3. Restore the previous overrides, or remove the current overrides to return to
   `config.py`. For example, as the service account:

   ```sh
   plum_settings_dir=/path/to/Plum-Island/webapp/.plum-settings
   mv "$plum_settings_dir/settings.json" "$plum_settings_dir/settings.failed.json"
   # If a previous version exists and is the desired recovery point:
   install -m 600 "$plum_settings_dir/settings.previous.json" "$plum_settings_dir/settings.json"
   ```

   In Docker, operate on the mounted directory corresponding to
   `/plum/data/settings`. If no previous file exists, leave `settings.json` absent
   to use `config.py`. Do not reuse an old revision while processes are running.
4. Restart the complete deployment, including the scheduler owner, and inspect the
   settings page and service logs. The controller publishes a fresh applied
   snapshot. Do not set `PLUM_SETTINGS_SNAPSHOT` manually on a web service.

Rolling application code back to a version before this feature makes GUI overrides
inactive. Restore the required operational values in `config.py` before that code
rollback, and preserve the private directory for possible forward recovery.
