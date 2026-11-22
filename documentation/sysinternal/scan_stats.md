# Scan activity counters

The **Status → Stats** page has two tabs: **Overview** retains the original
inventory totals; **Graphs** shows completed jobs, open port observations and
targeted ports as pastel line charts with points, with exact values
available under **View data**. Unavailable targeted-port counts break the line,
rather than being drawn as zeros. Selecting an interval or scanner immediately
reloads the graphs; there is no Apply button.
The graphs group completed scans by minute (last 60 minutes),
hour (last 24 hours), day (last 30 days) or month (last six calendar months,
including the current month). All interval starts are UTC; the
current interval is partial. A scanner selector separates Nmap and Masscan.
Both tabs use shared templates in the original and Plum themes. The Overview
tab does not query activity buckets; Graphs does not count search-index inventory.

## Counters

- **Jobs completed:** a result accepted by Island, including successful empty
  results. Interrupted jobs and rejected results do not count.
- **Open port observations:** distinct IP/transport/port pairs with state `open`
  in that job's report. Closed, filtered and bare service detections do not count.
  An IP/port observed in another job counts again: this measures activity, not
  the number of unique exposures in the search index.
- **Ports targeted:** intended IP/transport/port pairs, including targets that
  did not respond. This is not a packet counter and does not certify that every
  requested probe was sent before an individual host timeout.

New Island job responses include `report_target_count: true`. Updated agents
then return the optional integer `PORTS_TARGETED`. For Masscan, the agent counts
the union of the already resolved command targets, including overlapping CIDRs,
multiplied by the distinct requested TCP ports. No extra DNS lookup is made.
For Nmap, the agent uses the XML `runstats/hosts total` and `scaninfo numservices`
metadata, including down hosts. Missing metadata or a nonzero Nmap exit status
leaves the target count unknown. No result field is sent to an older controller
that does not request it. This preserves the old agent/Island contract.

Older agents remain accepted. If `PORTS_TARGETED` is absent, Island calculates
unique IP targets multiplied by distinct configured ports from the completed
job's stored `job` and `scan_ports` snapshot. Overlapping IPv4/IPv6 networks and
duplicate ports count once; networks are not expanded into individual addresses.
The agent value always takes precedence, including an explicit zero.
No DNS lookup, backend lookup or current scan-profile query is made. If the job
contains hostnames, lacks its port snapshot or contains invalid definitions,
the fallback is unavailable and targeted ports remain **Unknown**, not zero.
Mixed totals show the sum of known values and the number of jobs omitted.
This calculation measures intended probes; agent options may change actual
execution. Previously stored statistics are not retroactively recalculated.

## Storage and transactions

`scan_stat_buckets` is an ordinary table in the configured Plum SQL database,
compatible with MySQL/InnoDB and SQLite. Its composite primary key is
`(bucket_start, scan_tool)`. Four BIGINT counters store jobs completed, ports
targeted, open ports, and jobs missing a targeted-port count.

Result JSON is already decoded by the submission API. Counting open ports walks
that object once, without reading Meilisearch or Kvrocks. A conditional SQL update
claims the still-active job and its current bot/attempt. Only the winning request
increments the minute bucket through an atomic SQL upsert immediately before
commit, after target/profile synchronization, to minimize contention on that
shared minute row. Both changes commit
with the existing result-acceptance transaction. A rollback undoes both. Repeated
or simultaneous submissions therefore count once, even across a minute boundary.

No per-result event table, background aggregator, SQL job-table traversal or
search-index count is required. The Stats page reads bounded SQL aggregates on
the timestamp primary key. At most two rows are added per active minute, one
per scanner. Buckets have no automatic expiration in this first version.

Counters survive job cleanup, report retention and index rebuilds. Retagging,
historical imports and index reconciliation do not increment them. Collection
starts with this upgrade: previous jobs are not backfilled.

## Deployment

Existing SQLite installations receive migration **32** through `updisland.sh`,
with the updater's normal backup. For MySQL, apply
[`tools/sql/32_scan_stats_mysql.sql`](../../tools/sql/32_scan_stats_mysql.sql)
to the existing Plum database **before deploying the updated application**.
The SQLite updater does not apply MySQL schema changes. New installations create
the table through the normal SQLAlchemy metadata setup.

Upgrade Island before agents so that it accepts and requests the new optional
counter. No scan-index rebuild or historical rehash is needed for statistics.
