# Automatic detection updates

The scheduler observes committed tag rules and header collection configuration.
Imports through `tools/tag_mgmt.py` and edits/deletions through the GUI converge
through the same worker. A Git checkout alone does not import rules. The existing
UUID/YAML version policy still determines which imported definitions are accepted.
Names and descriptions do not cause reindexing. Dry runs do not change desired
state. Polling committed SQL state also recovers a crash between a rule save and
the next scheduler tick, without a separate SQL job migration.

The Tag Rules page shows automatic progress, the processing revision, pending
changes and errors. There are no manual update/reindex buttons. A browser is not
required for work to start, continue or recover. CLI status is available with:

```bash
.venv/bin/python tools/index_generation_admin.py status
```

## Process ownership and configuration

The existing scheduler supervises `tools/reconcile_index.py` as a separate Python
process. It does not perform the rebuild in a scheduler thread. SIGTERM/SIGINT
request a checkpointed stop; shutdown signals only the child owned by that
supervisor. The child exits between units when its parent disappears. Backend
calls use the configured connection timeouts. Restart resumes the frozen rule
and parser inputs, not whichever rules happen to be latest at that instant.

The scheduler must be running under the deployment's existing scheduler startup
contract; opening the GUI does not start it. The child explicitly removes
`WERKZEUG_RUN_MAIN` to prevent recursively starting another scheduler.

Initial tuning values in `webapp/config.py.template`:

| Setting | Default | Purpose |
| --- | --- | --- |
| `TAG_RECONCILIATION_ENABLED` | `True` | Allow the supervisor to run its child |
| `TAG_RECONCILIATION_POLL_SECONDS` | `30` | Observe desired state and supervise work |
| `TAG_RECONCILIATION_BATCH_SIZE` | `25` | Bounded planning/scanning/replay work per iteration |
| `TAG_RECONCILIATION_PAUSE_SECONDS` | `0.1` | Yield between iterations |
| `TAG_RECONCILIATION_PLANNING_BATCH_SIZE` | `1000` | Maximum IDs per inventory read, independent of capture batches |
| `TAG_RECONCILIATION_LATENCY_BUDGET` | `0.10` | Target maximum increase against comparable search baselines |
| `TAG_RECONCILIATION_QUIET_SECONDS` | `2` | Wait after foreground activity before resuming |
| `TAG_RECONCILIATION_IDLE_SECONDS` | `15` | Quiet interval before faster idle pacing |
| `TAG_RECONCILIATION_UNIT_SECONDS` | `0.05` | Soft duration target for the next inventory read |

Searches, IP detail reads, reports, exports and ingestion receive priority over
reconciliation. Authorized operations register short-lived activity leases; the
worker yields between captures and journal entries while these leases are live.
One heartbeat per web process renews leases, and crashed readers expire after
30 seconds. Passive progress polling does not register activity. After a quiet
interval the worker resumes, then accelerates during longer idle periods.

Inventory batches adapt to measured backend response time. Meilisearch starts
with smaller batches than Kvrocks; inventory size is independent of the number
of captures parsed per batch. A runtime pacing upgrade retains existing frozen
rules and planning cursors: it does not change the parser/index fingerprint.

The requested latency target is **at most +10%**. The controller compares a
request only with the same anonymized first-page query, dates and page settings,
using at least three timings recorded while background work was paused or
stopped. A measured excess increases pacing delays and the quiet interval.
Different queries and continuation pages are not mixed into a baseline. Queries
and IP addresses are not stored in this timing telemetry; its sample list and
baseline catalogue are bounded. Telemetry failure cannot fail a foreground read.

The progress page distinguishes waiting for activity from idle acceleration and
shows an observed timing difference only when comparable samples exist. This is
feedback toward the target, not a universal latency guarantee: an in-flight
backend command cannot be preempted, cold caches and other server load still
matter, and representative end-to-end measurements remain required.

These are starting settings, not throughput or availability guarantees. Smaller
batches and longer pauses reduce background load. A single large Kvrocks `COPY`
can still be expensive. Measure search latency, backend I/O and ingestion lag
before increasing throughput. Automatic retry uses exponential backoff, capped
at one hour; invalid snapshots remain blocked until corrected inputs arrive.

All processes writing one index must run on the same controller with the same
`PLUM_INDEX_STATE_DIR` (default `webapp/app/index_state`). The worker lock prevents
duplicate publishers; a separate write barrier serializes one capture update or
shadow update with publication. Multiple independent controller hosts are not
supported by these local locks. Durable state resides in Kvrocks, not the lock
directory. No new queue service is required.

## Work selection and coverage

Each run freezes executable rules, parser configuration and a code fingerprint.
Subsequent edits queue the latest desired revision. A normal rule-only update
uses normalized Kvrocks fields and previous per-rule contributions. It scans the
union of old matches and safe positive exact candidates when possible. Broad
expressions, tag dependencies and uncertain selection fall back to the full
required scope. Shared tags survive removal of one producer. Explicit tag
dependencies are evaluated in dependency order; cycles are rejected.

Coverage records reference the parser and HTTP collection profile actually used
for each capture. Unknown legacy coverage and missing required fields trigger
Meilisearch reparsing. Known absence differs from a field never indexed.
Non-exact HTTP header dependencies require explicit supported collection/rules;
they are reported instead of being treated as negative matches. Missing source
documents or parsing failures prevent publication and remain visible.
Changing the collection configuration reparses existing captures so historical
search fields and their coverage agree with the newly published profile.

The first migration may require a full historical reparse. For a full rebuild,
planning includes both existing Kvrocks UIDs and Meilisearch document IDs. That
work may still take the reported six hours. During planning and final catch-up,
progress is indeterminate; the capture-processing phase uses the deduplicated
candidate count. Completed processing is not reported as up to date until the
latest desired revision has been published.

## Generations, ingestion and search consistency

Managed keys use the reserved `plum:reconciliation:` prefix. Legacy logical keys
remain readable as the initial generation. A generation records a parent,
owned keys and deletion markers. Rule-only updates copy touched keys lazily;
they do not duplicate Meilisearch or copy the entire index for every edit.
Full rebuilds produce an independent generation. Kvrocks must support `COPY`
(available since 2.9.0 in the [official command catalogue](https://kvrocks.apache.org/docs/supported-commands/)).

The normal scheduler export passes source documents through the common ingestion
writer. It applies the published rules and journals captures before updating the
active index while a build is unfinished. Replay includes existing UID updates
and preserves accumulated `first_seen`/`last_seen`. The internal `delete_capture`
entry point journals removals; any future deletion caller must coordinate source
retention through that entry point. Direct external backend edits bypass this
protocol and are unsupported during managed operation.

Publication checks for an empty journal under the write barrier, then commits the
active pointer, published revision and completed state in one transaction. New
results remain in the normal durable job/JSON export pipeline during the barrier.
If ingestion outpaces catch-up, publication waits and the old generation stays
active; scanning is not frozen to force completion. Reduce scan/export pressure
or adjust measured worker capacity if the backlog does not converge.

All clients in a request, report or full JSON export share a generation. GUI
search sessions and signed Discovery API cursors retain that generation across
pages. Observed-tag caches include the generation in their cache key. InfoIP can
read missing protocols from Meilisearch without writing into a retired generation.

Generation retention protects existing readers. It also costs disk space and
adds lookup depth for successive incremental generations. Plan capacity for the
active data, shadow changes, contribution/coverage metadata, candidate UID sets
and ingestion journal. A periodic administrative full rebuild flattens ancestry.
No automatic deletion of old generations occurs while readers may still use them.

## Deployment, recovery and maintenance

Back up SQL configuration, Meilisearch source data and Kvrocks before rollout.
Do not start old and new writers against the same backend. Verify COPY support,
available storage, shared lock directory and scheduler startup. The first
scheduler observation queues migration automatically; it does not clear the live
legacy index. The published schema is not readable by older unmodified Plum code.

Legacy `tag_mgmt.py reindex` commands now queue scheduler work. `--flush` requests
a full background rebuild and never clears the active generation first:

```bash
.venv/bin/python tools/tag_mgmt.py reindex --allrules --flush
```

`tools/index_kvrocks.py --rebuild-from-meili` also queues a full background rebuild,
using the controller configuration and rejecting a mismatched output endpoint.
The old `--workers` and `--batch-size` flags do not tune this managed path; use the
controller settings above. Direct dump imports and older maintenance writers are
not permitted to mutate a managed generation; use the shared source ingestion
path or an isolated backend. In particular, destructive legacy flushes are not a
recovery mechanism for managed data.

Stop/restart the controller to exercise normal graceful stop/recovery. For a
planned parser/code upgrade, finish existing work first or allow the old snapshot
to become blocked: a new desired revision starts fresh staging without mixing
code versions. Backend failures retain the active generation and retry. Failed
publication acknowledgements are checked against the durable active pointer.

Jobs created by the earlier inline-snapshot format upgrade automatically. Their
original rules and journal remain frozen; an old scan cursor is replanned before
replay. Completed jobs and blocked jobs superseded by corrected inputs do not
require obsolete staging snapshots. If an unfinished compact job has genuinely
lost its frozen inputs, it is blocked with a recovery message instead of guessing
the rules. Queue an administrative full rebuild with `--flush` to replace it.

To undo rule changes, restore the desired rule definitions through normal GUI or
versioned YAML import (use a newer import version), then let reconciliation
publish them over current captures. Force a full rebuild when parser/index
coverage must be rebuilt. **Do not simply switch the active pointer to an old
generation:** it may omit captures received since that generation was retired.
Rolling back to older application code requires coordinated backend restoration
and replay of captures collected after the backup; retaining JSON/Meilisearch
sources and historical Kvrocks state is necessary for that procedure.

Retired managed generations and completed scratch/journal keys can be inspected
with a dry run. Applying cleanup requires every web/API reader, export, report
and controller to be stopped; the worker and write locks additionally guard the
operation. Active ancestors and unfinished staging remain protected. Unprefixed
legacy keys are retained deliberately. Unexpired signed API cursors also retain
their generation and its ancestors until their lease expires.

```bash
.venv/bin/python tools/index_generation_admin.py cleanup
# Only with all readers/controllers offline:
.venv/bin/python tools/index_generation_admin.py cleanup --offline --apply
```

## Validation before production rollout

Run the full test suite with a disposable SQLite configuration. The explicit
`test/index_reconciliation_integration.py` suite uses a dedicated local Redis
test socket and clears only its test database. It verifies protocol-level
generation/journal behavior; it does not substitute for a real Kvrocks benchmark.

On staging with representative data near two million captures, measure rule-only
updates, new-header reparsing and full rebuilding separately. Record first-result
and full-query latency/errors, export/ingestion lag, runtime, peak RAM/disk usage,
I/O, journal backlog and cutover duration. Establish acceptable latency and lag
targets with the operator before claiming production availability. Passing small
integration tests does not establish performance at that scale.
