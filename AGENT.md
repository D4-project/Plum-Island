# AGENT.md

## What Plum Does

Plum is not just a GUI. Plum is the orchestration server for remote scanning agents.
Its product goal is proactive surface-exposure discovery and monitoring.

Its production purpose is very simple:

1. store scan targets
2. create scan jobs from those targets
3. let remote agents fetch those jobs
4. receive scan results back from the agents
5. index those results for later search
6. keep those collected results queryable over time from the GUI

The most important rule to remember is this:

- Plum creates bounded jobs for agents.
- For IP ranges, a single job must not exceed 256 IPs.
- In practice, that means Plum serves work units no larger than `/24` worth of IPv4 addresses.

The normal runtime path is:

1. targets are stored in SQLAlchemy models
2. the scheduler turns eligible targets into queued jobs
3. agents poll `/bot_api/getjob` and receive one job
4. agents execute the scan remotely
5. agents send result JSON back through `/bot_api/sndjob`
6. Plum stores the raw JSON locally
7. Plum exports the result documents to Meilisearch
8. Plum exports parsed searchable fields to Kvrocks

This means most real changes are not “frontend-only” changes. They usually affect a pipeline spanning GUI, API, scheduler, JSON storage, and external search/index backends.

The collected scan data is meant to remain queryable with history, not just displayed once and discarded.

The local relational database is also easy to misunderstand:

- the local DB is SQLite in the default setup
- it stores application state, configuration-like objects, and orchestration metadata
- it stores things like targets, jobs, bots, API keys, scan profiles, ports, and NSE objects
- it is not the primary storage for scanned result data
- scanned result data lives first in local JSON files, then in Meilisearch and Kvrocks after export/indexing

Plum is therefore both:

- a scan orchestration server
- a search interface over collected scan results and their history

## What Plum Does Not Mean

Several directories can mislead a reader if they are skimmed without context:

- `webapp/app/jsons/` is not automatically proof of live production data. It is the runtime storage path for received scan results, but this repository can also contain copied JSON samples used for development, parser work, or local testing.
- `tools/` is not the main application runtime. It contains helper scripts for import, export, indexing, ad hoc maintenance, and experiments.
- `.venv/` is not application code. It is only a local Python environment artifact.

When you need to understand actual product behavior, prioritize:

- `webapp/app/__init__.py`
- `webapp/app/apis.py`
- `webapp/app/views.py`
- `webapp/app/scheduler.py`
- `webapp/app/models.py`
- `webapp/app/utils/result_parser.py`
- `webapp/app/utils/kvrocks.py`
- `webapp/config.py`

## Entry Points

- `webapp/run.py`: local dev launcher, runs Flask on `0.0.0.0:5001` with `debug=True`.
- `webapp/app/__init__.py`: creates Flask, SQLAlchemy, AppBuilder, loads views/APIs, and starts the scheduler only in the Werkzeug main process.
- `webapp/app/views.py`: GUI views, search pages, bulk target import, and job result file display.
- `webapp/app/apis.py`: bot-facing API plus target bulk import API.
- `webapp/app/scheduler.py`: background orchestration loop.
- `webapp/app/utils/result_parser.py`: transforms raw scan JSON into search documents.
- `webapp/app/utils/kvrocks.py`: secondary search index implementation.
- `webapp/config.py`: operational config for DBs, scheduler, Nmap profiles, JSON storage, and auth.

## Tests

All repository tests live under `test/`.

Before committing a code change, run:

```bash
.venv/bin/python test/run_all.py
```

For Python files touched by the change, also run:

```bash
.venv/bin/black <changed-python-files>
.venv/bin/python -m py_compile <changed-python-files>
PYLINTHOME=/tmp/pylint .venv/bin/pylint <changed-python-files>
```

If a test cannot run because it needs external services or local data, state that explicitly with the reason. Do not silently skip relevant tests.

## System Model

### Main entities

- `Targets`: scan inputs. Can be IPs, CIDRs, or FQDNs. `working` prevents duplicate job generation while a scan cycle is in progress.
- `Jobs`: units of work assigned to bots. Each job references one or more targets.
- `Bots`: remote scanner agents beaconing to the server.
- `ApiKeys`: bot authentication secrets.
- `ScanProfiles`, `Ports`, `Nses`: scan definition data model. Jobs are dispatched with profile-specific ports and NSE scripts.

### Effective runtime flow

1. Scheduler selects active, non-working targets whose `last_scan` is empty or older than `SCAN_DELAY`.
2. CIDRs are split into scan jobs of up to 256 IPs. In practice, the system builds jobs no larger than `/24` worth of IPv4 addresses. FQDNs are batched with the same 256-item ceiling.
3. A bot calls `/bot_api/beacon` to register/update liveness.
4. A bot calls `/bot_api/getjob` and receives a queued job plus the profile-specific `nmap_ports` and `nmap_nse` payload. NSE bodies are only transferred when the agent cache hash differs.
5. A bot calls `/bot_api/sndjob` with JSON results.
6. The result is stored under `JSON_FOLDER/<first-uid-char>/<job_uid>.json`.
7. Scheduler exports finished, non-exported jobs to Meilisearch and Kvrocks.
8. Old exported jobs are purged by `JOB_SCAVENGE`.

### Job priority contract

Scan profiles and jobs support five priority queues: `0` background, `1` low, `2` normal, `3` high, `4` urgent.

New jobs inherit `ScanProfiles.priority`; `Targets.priority` is metadata and does not drive scheduling today.
The GUI must constrain editable job/profile priorities to `0..4`.
The `Priority Boost` job action raises existing jobs to priority `4`.
When a scan profile is edited, `ScanprofilesView.pre_update()` marks `priority_retag_pending`.
The scheduler must converge queued unfinished jobs for that profile to the current profile priority in batches controlled by `SCHEDULER_PRIORITY_RETAG_BATCH_SIZE`.
Always read the current `ScanProfiles.priority` during each batch; do not store a stale target priority. If the profile changes priority again mid-retag, the remaining scheduler batches must converge to the newest value.
Only jobs with `active = 0` and `finished = 0` are retagged.

Agents receive jobs through `/bot_api/getjob`.
That endpoint must use dynamic smooth weighted round-robin over the queues that are currently non-empty, with these base weights:

- `4`: 50
- `3`: 20
- `2`: 15
- `1`: 10
- `0`: 5

Do not replace this with a fixed fallback list that lets empty high-priority slots collapse permanently onto the next highest queue.
Only queue availability is needed at request time; do not count full queue sizes.
The waiting-job lookup depends on the `idx_jobs_waiting_priority_creation` index created by migration 13.

The orphan working-state repair in `task_create_jobs()` must stay batched.
`SCHEDULER_ORPHAN_SWEEP_BATCH_SIZE` caps how many stuck `target_scan_states` rows are released per sweep, and migration 13 provides `idx_target_scan_states_working_target_profile` for that lookup.
It must first select a bounded candidate window by `target_scan_states.id` using `scheduler_orphan_sweep_cursor_id`, then evaluate the orphan `NOT EXISTS` check only inside that candidate set.
Do not reintroduce a global correlated `UPDATE target_scan_states ... WHERE working = 1 AND NOT EXISTS (...)` or a global orphan `SELECT` over the full table; it can block SQLite for minutes on production-sized queues.

### NSE synchronization

- The agent keeps a local cache of controller-managed NSE files under `src/nse_cache/`.
- On every `/bot_api/getjob`, the agent sends `NSE_HASHES`, a `{filename: sha256}` map for its local NSE cache.
- The controller compares each requested NSE against the hash stored in the `Nses` table.
- If the agent already has the expected hash, the controller sends only `{name, hash}` for that NSE.
- If the hash is missing or different, the controller also sends `content_b64` so the agent can refresh its local copy.
- The agent validates the received SHA-256 before replacing the cached file, then runs Nmap with the cached file path.
- Agent logs explicitly show `NSE cache hit: <name>` or `NSE cache refresh: <name>` for each script used by a job.

### Storage and indexing roles

- SQLAlchemy/SQLite: local relational application state for targets, jobs, bots, API keys, scan profiles, and orchestration metadata. It is not the database of scanned host result content.
- Local JSON files in `JSON_FOLDER`: raw job result files received from bots.
- Meilisearch: stores exported host documents derived from scan JSON so documents can be retrieved again by UID and explored from the UI.
- Kvrocks: stores the keyword index built from parsed results and powers fielded search such as `ip`, `net`, `fqdn`, `http_server`, `x509_subject`, and similar criteria.

Do not describe Kvrocks as “Redis” in project documentation. The code uses the Redis protocol client library to talk to a Kvrocks server, but the backend product in this project is Kvrocks.

### Domain detection rules

Domain extraction in `result_parser.py` is guarded. Plum does not index every string that merely looks like a hostname.

The current contract is:

- `ONLINETLD = False`: validate suffixes offline with `py-faup-rs` built-in knowledge. This is the fast offline mode.
- `ONLINETLD = True`: validate suffixes against the explicit `TLDS` list loaded at startup. In the web app, that list is refreshed from IANA when enabled.
- `TLDADD`: extra suffixes that are always accepted in addition to the main validation mode, for example `local`.

So `TLDADD` is an allow-list override, not the primary detection mechanism.

If a suffix is accepted, Plum may populate all of these parsed fields:

- `fqdn`
- `host`
- `domain`
- `tld`

If these fields are missing in Kvrocks while isolated parsing works, check this order first:

1. the parser config actually passed to `parse_json()`
2. whether `ONLINETLD` and `TLDS` or offline suffix detection match the intended mode
3. whether `TLDADD` contains the local/private suffixes you expect
4. whether the data was indexed before the parser/config fix and therefore needs reindexing

### Search modes exposed in the GUI

Plum exposes two distinct search pages and they do not serve the same purpose:

- `Token Search` uses Meilisearch. This is the broad, free-form, word-based search page. It is useful when the user wants to search scan documents more loosely and inspect matching raw bodies quickly.
- `Search Scans` uses Kvrocks. This is the structured search page, closer to a Shodan-like experience. It accepts fielded filters such as `ip`, `net`, `port`, `http_server`, `http_title`, `x509_subject`, `banner`, and similar parsed attributes.

The structured search page is the more operational one:

- it groups results by IP
- it shows timestamps for first/last seen data
- it expands to matching UIDs
- it fetches the full stored document from Meilisearch when a UID is opened
- it defaults to a date range from today back to today minus 3 months
- it normalizes the selected date range to `00:00:00` on the start date and `23:59:59` on the end date
- it renders only the first 100 IPs at a time for responsiveness and resumes with `Load more`
- it uses an adaptive backward scan by `last_seen`: start at 1 day, grow to 2/4/8/... days when empty, then fall back to 1 day once hits are found
- it can export the matching IP list and the full matching JSON set

So the split is:

- Meilisearch page = token/document search
- Kvrocks page = structured analyst search over indexed result fields

The structured search capability is part of the product, not an auxiliary admin feature. The README presents these fields as the way to explore collected exposure data.

### IP detail view

The structured search page links each IP to `/ip/<ip>`. That page is not a raw document dump; it is a cumulative history view for one IP across all matching stored scans.

Its current contract is:

- the `Scans Results` tab aggregates observations by port
- each port card contains timestamp tabs ordered oldest on the left and newest on the right
- the most recent timestamp tab is selected by default
- a `Requested Hostname` dropdown is rendered before the port cards
- the dropdown always includes `IP only` first, then all `fqdn_requested` values for that IP in alphabetical order
- selecting a hostname filters the visible observations client-side without reloading the page
- the `Informations` tab is separate and is used for external enrichment such as CIRCL geolookup and passive DNS

If you change how `body.hostnames` is parsed or indexed, verify both structured search and `/ip/<ip>` together. The IP detail page now depends on the same `type == "user"` hostname semantics as `fqdn_requested`.

## Files That Matter By Task

### If you change target ingestion

- `webapp/app/views.py`
- `webapp/app/apis.py`
- `webapp/app/utils/mutils.py`
- `webapp/app/models.py`

Bulk import logic lives in `TargetsView.do_bulk_import()`. It accepts newline-separated FQDN/IP/CIDR values and normalizes CIDRs through `is_valid_ip_or_cidr()`.

### If you change bot protocol or job assignment

- `webapp/app/apis.py`
- `webapp/app/models.py`
- `webapp/config.py`

Bot payload validation is Marshmallow-based in `BotInfoSchema`. Keep wire compatibility in mind before changing field names like `UID`, `JOB_UID`, `RESULT`, or `AGENT_KEY`.

### If you change scheduling or export behavior

- `webapp/app/scheduler.py`
- `webapp/app/models.py`
- `webapp/app/utils/result_parser.py`
- `webapp/app/utils/kvrocks.py`

This is the core orchestration path. Small mistakes here can stall scans, duplicate work, or desynchronize `Targets.working`, `Jobs.finished`, and `Jobs.exported`.

### If you change search

- `webapp/app/views.py`
- `webapp/app/utils/kvrocks.py`
- `webapp/app/utils/result_parser.py`
- `webapp/app/templates/search_meili.html`
- `webapp/app/templates/search_kvrocks.html`
- `readme.md`

The search syntax exposed in the UI and README must stay aligned with the fields actually produced by `parse_json()` and indexed by `KVrocksIndexer.add_documents_batch()`.

For the structured search page specifically, keep these moving parts aligned:

- `KVSearchView.parse_query()` for accepted keywords and modifiers
- `KVSearchView.execute_search()` for the full search/export semantics
- `KVSearchView.execute_search_page()` for the fast paged UI semantics
- `search_kvrocks.html` for the help table, default date handling, and adaptive loading behavior
- `result_parser.py` plus `KVrocksIndexer.add_documents_batch()` for the actual indexed field names

## Parsing And Search Contract

The parser in `webapp/app/utils/result_parser.py` expects per-host result objects shaped roughly like:

- top-level `id`
- top-level `ip`
- top-level `body`
- `body.ports[*].portid`
- `body.ports[*].scripts[*]`

It extracts these searchable fields:

- `fqdn`
- `fqdn_requested`
- `host`
- `domain`
- `domain_requested`
- `tld`
- `tag`
- `port`
- `http_title`
- `http_cookiename`
- `http_etag`
- `http_server`
- `http_favicon_path`
- `http_favicon_mmhash`
- `http_favicon_md5`
- `http_favicon_sha256`
- `x509_issuer`
- `x509_md5`
- `x509_sha1`
- `x509_sha256`
- `x509_subject`
- `x509_san`
- `banner`

Raw scan documents, including the Meilisearch source documents, never carry `tag` or `tags` fields. Tags are computed from DB-backed tag rules while parsing for the Kvrocks index. Canonical stored tag values use `<namespace>:<value>` such as `product:openssh` or `proto:ssh`; Kvrocks query/index keys use `tag:<namespace>:<value>` and `tags:<uid>`. Do not add Meilisearch fallbacks for tags or merge "pre-existing document tags" into computed tags.

`fqdn_requested` is not a synonym of `fqdn`. It is derived only from `body.hostnames[*]` entries whose `type == "user"`. This field is used both by structured search and by the hostname selector on `/ip/<ip>`.

### Reporting contract

Reports are configured from the `Reports` model and use the structured Kvrocks query syntax.
The query is always evaluated inside the report interval. Monthly reports use `last_run_at` as the start when available; otherwise they start one calendar month before the run time.

Report output is Markdown only for now. Keep the current shape aligned between code and README:

- summary and period
- open port summary
- monthly `New opened port` comparison before the host list
- host list sorted by numeric IP order
- per-host tags from Kvrocks `tags:<uid>` only; scan documents and Meilisearch documents do not contain tags
- per-host open ports and scan result count
- per-host associated FQDNs from PTR records found in report-period documents first, only when the source document `last_seen` is within `REPORT_PTR_LAST_SEEN_MONTHS` months before the report end, then `fqdn_requesteds:<uid>`, completed by Passive DNS `A` records up to 25 total entries
- report-period PTR entries are rendered with `(ptr)`
- requested FQDNs win over Passive DNS duplicates; Passive DNS-only entries are rendered with `(pdns)`
- the as-is disclaimer

The `Preview` action must not send email and must remain available for inactive reports.
Preview generation is asynchronous because Passive DNS enrichment can be slow:

1. `/reportsview/preview_loading/<id>` renders the progress modal.
2. `/reportsview/preview_start/<id>` starts a background preview job.
3. `/reportsview/preview_status/<job_id>` returns progress, including `Resolving Passive DNS X/XX`.
4. `/reportsview/preview_result/<job_id>` renders the completed Markdown.

All report preview routes must stay protected with `@has_access`.
Preview job state must stay bound to the creating authenticated user before exposing status or rendered Markdown.

The structured query syntax currently works like this:

- terms are `field:value`
- quoted values are allowed because parsing is `shlex`-based, for example `http_title.lk:"index of"`
- implicit `AND` inside one group
- explicit `OR` between groups
- repeated occurrences of the same key inside one group accumulate into a list
- supported suffix modifiers are `.lk` / `.like`, `.bg` / `.begin`, and `.not` / `.nt`

Time filtering also has two distinct semantics and they must not be conflated:

- full search and export use overlap logic on the document interval `[first_seen, last_seen]`
- fast UI paging scans one backward `last_seen` window at a time for responsiveness

That distinction is intentional. The UI is optimized to show the first results quickly; the exports must cover the full matching set.

If you add a new parsed field, update all of:

1. `default_parsing` or helper functions in `result_parser.py`
2. `KVrocksIndexer.add_documents_batch()` keyword list
3. `KVSearchView.parse_query()` allowed keywords if the field must be queryable
4. `readme.md` search documentation

If you skip one of these, the feature will look half-implemented.

Also keep the split of responsibilities clear:

- Meilisearch receives the exported JSON-like host documents.
- Kvrocks receives the denormalized field index derived from those documents.

The README-level search contract currently includes:

- exact fields such as `ip`, `net`, `port`, `http_favicon_mmhash`, `http_favicon_md5`, `http_favicon_sha256`, `x509_md5`, `x509_sha1`, `x509_sha256`
- prefix or substring search on fields such as `fqdn`, `fqdn_requested`, `host`, `domain`, `tld`, `tag`, `http_title`, `http_cookiename`, `http_etag`, `http_server`, `http_favicon_path`, `banner`, `x509_issuer`, `x509_subject`, `x509_san`
- abbreviated modifiers `lk` for `like` and `bg` for `begin`
- implicit `AND` inside one query group
- explicit `OR` between query groups

Keep `AGENT.md`, `README`, parser output, and `KVSearchView.parse_query()` aligned. If one changes without the others, the analyst-facing search model becomes misleading.

## Operational Assumptions

- Flask-AppBuilder is the admin/UI framework.
- SQLite is the default local relational DB in dev, used for app state and objects rather than scanned result storage.
- Meilisearch and Kvrocks are expected to be running externally.
- Scheduler startup has side effects at import time in `webapp/app/scheduler.py`.
- When `ONLINETLD = True`, app startup performs a live TLD download via `fetch_tlds()`.
- `webapp/app/jsons/` may contain copied sample scan results useful for development and parser work; do not assume this directory reflects live production data.
- `tools/` contains helper scripts for import, export, indexing, and ad hoc maintenance; it is not the main runtime path of the web application.

Because of those side effects, avoid importing scheduler modules in tests unless you actually want scheduler/bootstrap behavior.

## Flask-AppBuilder Access Control

Custom Flask-AppBuilder UI routes are easy to expose accidentally. Treat this as a recurring project risk.

When adding or editing any `@expose(...)` method on `BaseView` or `ModelView` classes in `webapp/app/views.py`, add `@has_access` unless the route is intentionally public and that exception is explicitly documented in the code.

The expected pattern is:

```python
@expose("/some_route")
@has_access
def some_route(self):
    ...
```

Do this for download/export/status/helper routes as well as normal HTML pages. Flask-AppBuilder then creates method-level permissions such as `can_export_zip`, `can_preview_status`, or `can_targets_remote`; leaving off `@has_access` can bypass the role model.

Before finishing a change in `views.py`, search for newly added custom routes and verify every `@expose` has a matching `@has_access` nearby:

```bash
rg -n "@expose\(|@has_access" webapp/app/views.py
```

`webapp/app/apis.py` has separate API authentication patterns. Bot-facing routes are not Flask login routes, but they must still fail closed through agent-key validation plus server-side ownership checks such as bot/job assignment.

## Known Sharp Edges

These are already visible in the code and should be preserved carefully or fixed deliberately, not accidentally:

- `scheduler.py` performs backend initialization and starts APScheduler at import time.
- `__init__.py` guards scheduler import with `WERKZEUG_RUN_MAIN == "true"` to reduce duplicate starts in debug mode.
- Job files are sharded by the first character of job UID. Any code that reads/writes result JSON must use that layout.
- The repository can contain copied scan result JSON under `webapp/app/jsons/`; treat them as fixtures or local artifacts unless the user explicitly says they are current runtime data.
- Scripts under `tools/` are operational helpers, not evidence that the main app always depends on them during normal execution.
- Local virtualenv directories such as `.venv/` are environment scaffolding only; do not inspect them for product behavior.
- SQLite is used for local application objects and orchestration state, not as the main scanned-data store.
- Kvrocks is the result indexing backend. Do not rewrite docs or code comments as if the project were using plain Redis as the product dependency.
- `Targets.working` is part of the de-duplication mechanism for job generation. Do not change it casually.
- The parser relies on specific Nmap/NSE output keys and does key normalization by replacing spaces/hyphens with underscores.
- Search is implicit `AND` within one group and explicit `OR` between groups. Repeated same-key terms are accumulated into lists inside each group, then merged across OR groups at the view layer.
- Several areas still contain debug prints or assumptions that are acceptable in dev but risky in production.

## Editing Guidance

### Good changes

- Keep bot API payloads backward-compatible unless the agent implementation is updated in lockstep.
- Keep search keyword names stable unless you also update docs and indexers.
- Prefer narrow changes in scheduler/export code and reason through state transitions.
- Preserve existing file sharding under `JSON_FOLDER`.

### Risky changes

- Refactoring `task_create_jobs()`, `sndjobs()`, or `task_export_to_dbs()` without tracing the full lifecycle.
- Changing model flags like `working`, `active`, `finished`, `exported` without updating every consumer.
- Changing result JSON structure without updating `parse_json()`.
- Importing application modules in standalone scripts without understanding startup side effects.

## Local Development Notes

Typical local run path:

```bash
cd webapp
python run.py
```

Configuration lives in:

- `webapp/config.py`
- `tools/config.yaml` for some helper scripts

Useful helper scripts live under `tools/`, including parse/index/search utilities, but they are auxiliary workflows rather than permanent application runtime components.

## Minimal Verification After Changes

Choose the smallest set that matches your edit:

- GUI/import change: exercise target creation and bulk import.
- Bot API change: validate `/bot_api/beacon`, `/bot_api/getjob`, `/bot_api/sndjob` payload handling.
- Parser/index change: run `.venv/bin/python test/run_all.py` and `test/test_parse.py` with a representative fixture when parser output needs manual inspection.
- Search change: confirm query parsing in `KVSearchView.parse_query()` and index field availability in Kvrocks.
- Scheduler change: verify job creation, export marking, and cleanup state transitions.

## Recommended Mental Model For Future Agents

Think of Plum as an orchestration pipeline, not a CRUD app:

- SQL DB is the source of truth for targets, jobs, bots, configuration objects, and lifecycle state.
- JSON files are the durable handoff between bot result ingestion and indexing.
- Meilisearch stores exported host JSON documents for retrieval and document-oriented exploration.
- Kvrocks stores denormalized keyword indexes for fast fielded search over parsed result attributes.

Most non-trivial bugs come from breaking the contract between those four layers.
