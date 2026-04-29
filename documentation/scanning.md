# Scan Profiles, Scheduling, and Priority

Plum Island schedules scans per `Target x ScanProfile`.
This means one target can have multiple independent scan states at the same time, one for each effective profile.

## Per-profile scan stats

The authoritative runtime stats are stored in `target_scan_states` and visible in:

- `Status -> Profile Scans`
- the `Profile Scan Stats` table on `/targetsview/show/<id>`

For each `target/profile` pair, Plum tracks:

- `working`: at least one job for this target/profile is still running or pending
- `last_scan`: completion time of the latest finished scan cycle for this target/profile
- `last_previous_scan`: completion time of the previous finished scan cycle for this target/profile
- `cycle`: time delta between `last_scan` and `last_previous_scan`

## Scan execution parameters

Ports and NSE scripts are resolved exclusively from the effective `ScanProfile`.
There is no global fallback list in `config.py`.

When an agent fetches a job:

- `nmap_ports` comes only from the job/profile
- `nmap_nse` comes only from the job/profile
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
