# Scan Profiles, Scheduling, and Priority

Plum Island schedules scans per `Target x ScanProfile`.
This means one target can have multiple independent scan states at the same time, one for each effective profile.

## Agent requirement

Plum Island does not run scans directly from the web application.
Scans are executed by one or more Plum Agent instances.

The agent is available here:

- <https://github.com/D4-project/Plum-Agent>

Each agent connects back to Plum Island, asks for a job, downloads the required NSE scripts when needed, runs the scan, then sends the result back to the web application.
Agents visible to the server are listed in:

- `Status -> Bot Status`

## Agent API keys

Before starting an agent, create an API key for it in the Plum Island web UI:

1. Open `Security -> Agent Keys`.
2. Click `+` / `Add`.
3. Save the generated key immediately.

The key is only shown at creation time.
After saving, Plum Island stores a hashed copy and only keeps the key identifier visible.

Use this generated key as the agent access key in the Plum Agent configuration.
The agent sends it as `AGENT_KEY` when calling the bot API endpoints.

## Per-profile scan stats

The authoritative runtime stats are stored in `target_scan_states` and visible in:

- `Status -> Profile Scans`
- the `Profile Scan Stats` table on `/targetsview/show/<id>`

For each `target/profile` pair, Plum tracks:

- `working`: at least one job for this target/profile is still running or pending
- `last_scan`: completion time of the latest finished scan cycle for this target/profile
- `last_previous_scan`: completion time of the previous finished scan cycle for this target/profile
- `cycle`: time delta between `last_scan` and `last_previous_scan`

## Target metadata and network information

Target details show insertion time (UTC), IPv4 CIDR / IPv6 CIDR / FQDN type,
and structured AS information separately from the editable description. Bare IPs
are host networks. AS records are shared by ASN; coordinates are **country
averages**, not host or AS geolocation. Legacy `as_bgp`, `as_description` and
`as_country` Python accessors read this shared record; old SQL columns are retained
only for rollback and are no longer authoritative.

FQDN validation and registered-domain extraction use `pyfaup-rs` offline. This
handles public suffixes such as `co.uk`; optional `TLDADD` in `webapp/config.py`
and `tools/config.yaml` accepts private suffixes such as `local`. The old
`ONLINETLD`/`TLDS` settings are ignored. The target's WHOIS tab queries the
registered domain for FQDNs, or the network for IP/CIDR targets, only when opened.
Unknown/private suffixes have no public domain WHOIS lookup.

New CIDRs automatically queue enrichment. Every accepted scan receipt checks each
associated target and queues a lookup when its data is missing or its last
successful lookup is **older than 24 hours**. Exactly 24 hours is still fresh.
The dedicated `network_enrichment` scheduler job consumes this durable queue at
`SCHEDULER_DELAY`, independently of scan orchestration and export. FQDNs are never
resolved or enriched by this feature. Editing the target value clears old network
metadata and schedules a new lookup only if the new value is a CIDR/IP.

Requests use `https://ip.circl.lu/geolookup/<network-address>`: only the first
address of the CIDR, including IPv6. The ASN-bearing response entry determines the
AS for the entire CIDR, even if other addresses belong to another AS.

The detail button and list **Refresh Network informations** action force an
immediate lookup regardless of age/backoff. If a lookup is already running, the
action reports `busy` instead of duplicating it. Both actions require a form POST
with CSRF protection and their FAB permission: `can_refresh_network` and the
existing `mulresolvehwois`, respectively, on `TargetsView`. The configured role
seed grants the detail action alongside its existing list action; administrators
should grant the new permission to equivalent custom roles. Unauthorized controls
are hidden and direct requests are checked server-side.

The configurable HTTP timeout is `NETWORK_LOOKUP_TIMEOUT_SECONDS` (initially 10 s,
matching the existing geolookup proxy); `NETWORK_REFRESH_BATCH_SIZE` (initially 32)
limits each automatic pass. The worker also uses the existing queue-generation
time budget between lookups. These are initial operational settings, not throughput
guarantees; tune with production latency. No HTTP request holds a SQL write
transaction. A durable per-target lease lasts three timeout intervals and allows
recovery after a process restart. Failures keep previous data and successful-refresh
time and log a warning. Missing or stale data is retried no earlier than the next
scheduler interval; a failed forced refresh does not invalidate still-fresh data.
Insertion and scan receipt never depend on a successful CIRCL response.

For existing installations apply migration 23 before starting this code; see
[migration instructions](migration.md#target-network-metadata-migration-23).

## Scan-profile cycle boundaries

Each scan-profile cycle stores `max_target_id`, the highest `Targets.id`
visible when the scheduler starts that cycle. The current cycle schedules and
reconciles only active applicable targets whose ID is at or below this bound.

Targets created later have a higher ID and wait for the next cycle. Continuous
target imports therefore do not extend a running cycle indefinitely. An older
target associated with an explicit profile during a cycle may still join the
current cycle because target ID is the only membership boundary.

Within a running cycle, targets with `last_scan >= cycle.started_at` are not
scheduled again, even if their rescan delay has elapsed. Never-scanned targets
and targets last scanned before the cycle started remain eligible under the
normal rescan-delay rules. This boundary uses persisted timestamps and survives
restarts. Once the cycle finishes, the next cycle can schedule targets whose
rescan delay has elapsed.

This correction requires no database migration or manual state reset. Existing
queued and active jobs finish normally; the cycle closes when all applicable
targets are complete and no unfinished job remains. A running cycle at 100%
shows `finalizing` until those conditions are met.

The Scan Profiles list tooltip and profile detail page expose incomplete target,
queued job, and active job counts when a cycle remains running. A stalled active
job is requeued by the scheduler watchdog after two hours; orphaned working
states are released by the existing bounded repair sweep.

During migration, existing running cycles receive the current maximum target
ID. Their queued and active jobs, target state, and progress remain unchanged.

## Search export ordering

Finished scan results are always exported to Meilisearch before Kvrocks. The
scheduler submits at most one 2,500-document Meilisearch batch, stores its task
UID and per-job document position in SQLite, then immediately yields so scan job
generation cannot be delayed by Meilisearch indexing.

Scan orchestration and search-backend maintenance use independent scheduled
jobs. A slow export or report tick therefore cannot consume the
`scan_orchestration` job's single running-instance slot.

If the task remains `enqueued` or `processing`, the scheduler does not write
Kvrocks and does not mark jobs exported. On later ticks it checks the same task
UID once without resubmitting the batch. Only `succeeded` permits the matching
Kvrocks documents to be written. A multi-batch job is written to Kvrocks only
after every Meilisearch batch for that job has succeeded.

A failed or canceled Meilisearch task clears the saved submission position. The
job remains unexported and is safely upserted again on a later scheduler tick.
Individual Meilisearch HTTP requests are bounded by
`MEILI_HTTP_TIMEOUT_SECONDS`, and Kvrocks socket operations by
`KVROCKS_SOCKET_TIMEOUT_SECONDS`; both default to 10 seconds.

The `/bot_api/sndjob` log reports one accepted scanner JSON file and its number
of top-level scan results after the job commits. The scheduler's
`finished export_to_dbs` line reports `scanner_json_files_pending` (finished
jobs awaiting complete export at the start of the tick), `scanner_json_files_read` and
`scan_results_read` for this tick, `port_documents_split` (per-port documents
generated before parser filtering), `documents_submitted` (sent to Meilisearch),
and `documents_integrated` (confirmed in Meilisearch and written to Kvrocks).
Submission and integration normally happen on different ticks. Split/read counts
measure work performed in that tick, so retries or multi-batch jobs can repeat
them; they are not lifetime unique totals.

## Scan execution parameters

Ports and NSE scripts are resolved exclusively from the effective `ScanProfile`.
There is no global fallback list in `config.py`.

When an agent fetches a job:

- `nmap_ports` comes only from the job/profile
- `nmap_nse` comes only from the job/profile
- `nmap_additional_params` is an optional profile snapshot containing shell-free Nmap argv tokens
- profile parameters are empty by default; older agents ignore this additive payload field
- agents that support the field may use duplicate options to override their defaults
- NSE files are synchronized to the agent by filename and SHA-256 hash
- the file body is transferred only when the agent cache does not already have the expected hash

## Global target stats

The legacy fields on `targets` are kept as global aggregates:

- `Targets.working`: `True` if any profile for this target is currently working
- `Targets.last_scan`: completion time of the latest finished profile on this target
- `Targets.last_previous_scan`: previous value of the global `last_scan`
- `Targets.duration_html()`: delta between the two global timestamps above

These global values do not represent a full multi-profile scan cycle.
They only represent the last scan event observed on the target, regardless of which profile produced it.
For operational tracking, prefer the per-profile stats.

## Job priority

Scan profiles and jobs support five priority queues:

| Priority | Meaning |
| -------- | ------- |
| `0` | background |
| `1` | low |
| `2` | normal |
| `3` | high |
| `4` | urgent |

New jobs inherit the priority of their scan profile.
The `Priority Boost` action on an existing job raises it to priority `4`.

When a scan profile priority changes, already queued unfinished jobs are retagged gradually by the scheduler.

Relevant settings:

- `SCHEDULER_PRIORITY_RETAG_BATCH_SIZE`: queued jobs updated per profile and scheduler tick
- `SCHEDULER_ORPHAN_SWEEP_BATCH_SIZE`: stuck target/profile working states repaired per orphan sweep

## Queue selection

When agents request work, Plum uses a dynamic weighted round-robin over the queues that currently have waiting jobs.

Base weights:

| Priority | Weight |
| -------- | ------ |
| `4` | 50 |
| `3` | 20 |
| `2` | 15 |
| `1` | 10 |
| `0` | 5 |

Only non-empty queues are considered.
If urgent and high queues are empty, remaining capacity is redistributed across the lower queues instead of being pinned to a fixed fallback order.
