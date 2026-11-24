# External lookup caching

Plum shares successful external lookup responses between the web application,
reports, exports and target enrichment. This cache is separate from search data,
SQL enrichment snapshots and browser state.

## Policies and configuration

Administrators configure these positive integer durations under **Security → Plum
Settings → External lookup caching**. Defaults also appear in `config.py.template`.
Saving requires restarting **Plum-Agent**; the global pending-configuration banner
remains visible until the saved configuration is applied.

| Configuration key | Default | Source and identity |
| --- | --- | --- |
| `WHOIS_CACHE_HOURS` | 24 hours | Final WHOIS text per canonical IP or exact CIDR |
| `PDNS_CACHE_HOURS` | 12 hours | CIRCL passive observations per IP and credential scope |
| `IP_INFO_CACHE_HOURS` | 24 hours | Combined CIRCL geolocation and AS response per queried IP |

IP and AS information come from one CIRCL response. Their shared lifetime also
controls the freshness threshold for the SQL target-enrichment workflow.

An IP and its `/32` or `/128` form share a WHOIS key. Equivalent IPv6 spellings
normalize identically. A CIDR has its own WHOIS key: a host response never stands
in for a network response. Geolocation for a target CIDR queries its first IP,
matching existing target-enrichment semantics; it does not enumerate the range.

## Request flow

1. The page renders without waiting for external enrichment. Its `fetch` request
   reaches the existing permission-checked route. Target details use
   `TargetsView.network_info`, with the same show permission and row filters.
2. The server normalizes the query and checks Kvrocks.
3. A fresh hit returns immediately, without contacting the upstream provider.
4. A miss acquires a distributed lease, rechecks the cache and fetches the source.
   Concurrent callers wait for the same response instead of launching duplicates.
5. Successful data and its expiry are written atomically. The page displays the
   result and its original fetch time in the browser’s local time zone.

Reports and exports call the same source service directly, without HTTP calls
back into Plum. There is no cache prewarming, scheduled refresh or sweeping job.

The expiry starts when source retrieval completes. Reading a key does not extend
its validity. A key expires even if nobody consults it. After expiry, the next
request fetches again; an expired response is never presented as current. Changing
a duration uses a different cache key after restart; previous entries expire
under their original policy.

## Implementation and storage

- `webapp/app/utils/lookup_cache.py`: raw Kvrocks client, cache records, fixed
  expiry, distributed leases and metadata.
- `webapp/app/utils/enrichment_cache.py`: source-specific normalization, WHOIS,
  Passive DNS transport, credential isolation and combined IP/AS responses.
- `webapp/app/utils/reports.py` and `resolved_export.py`: consume shared PDNS
  observations, then apply their own selection, time-range and output rules.
- `webapp/app/utils/circl_lookup.py`: fixed IP/AS HTTP transport shared with
  standalone diagnostic helpers.
- `webapp/app/utils/ip2asn.py` and `network_enrichment.py`: derive structured AS
  data while retaining the original source retrieval timestamp.

Keys are in database 0, outside `GenerationClient`:

```text
plum:lookup:v1:whois:<canonical-network>:ttl:<seconds>
plum:lookup:v1:pdns:<credential-scope>:<canonical-ip>:ttl:<seconds>
plum:lookup:v1:ip-info:<canonical-ip>:ttl:<seconds>
```

Each JSON record contains `value`, `fetched_at` and `expires_at` (UTC epoch
seconds). Responses add `cached`; this is a property of the current lookup.
WHOIS endpoints expose freshness under the JSON `cache` field. Existing array
responses for PDNS and geolocation remain arrays; freshness uses
`X-Lookup-Cache`, `X-Lookup-Fetched-At` and `X-Lookup-Expires-At` headers.
These HTTP responses use `Cache-Control: no-store` where appropriate: server
Kvrocks caching does not require a browser cache of private enrichment data.

Source identity includes the service namespace. Search rebuilds and generation
switches neither move nor invalidate these keys. There is no SQL migration.

## Passive DNS boundaries

`PDNS_ENABLED = False` prevents both cached reads and CIRCL requests. New
installations default to disabled; old configurations without the key continue
using Passive DNS when both credentials exist. Explicit `False` takes precedence.
Failed lookups are never cached. Reports and exports continue with incomplete
PDNS data and record a warning; the IP view distinguishes rejected credentials,
timeouts and invalid upstream responses.

The cache holds complete parsed observations before report-specific filtering.
A report can reuse an IP-detail lookup and vice versa. Successful empty PDNS
results are cached. Failures and malformed or partial responses are not.

The credential scope is an HMAC-SHA3-512 fingerprint keyed by the deployment
`SECRET_KEY`, covering both CIRCL username and password with unambiguous encoded
boundaries. Raw credentials never appear in keys, metadata or logs. Changing
credentials or the deployment secret creates a different namespace. Without a
deployment secret, shared credential caching is skipped.

Configured credentials and route permissions are checked before serving data.
The cache does not store signed DNS-resolution tokens: `/ip` generates fresh
ones from cached observations for each response. Live DNS verification remains
an explicit action and has its own existing behavior.

## Target snapshots and forced refresh

The target page fetches IP/AS data asynchronously. It does not wait for a scheduler
cycle or perform synchronous network requests while rendering the page.

SQL `Targets` and `AutonomousSystems` remain durable enrichment snapshots for
existing consumers. Their records do not disappear when a cache key expires.
When enrichment reuses a cached response, the target's source timestamp remains
the original fetch time, preventing repeated reuse from falsely renewing freshness.

**Refresh Network informations** retains its existing permission and CSRF checks.
It bypasses the IP/AS response cache, retrieves fresh data, updates the shared cache
and persists the target snapshot. Existing target claim checks still prevent stale
results from applying after a concurrent target edit.

## Concurrency and failures

Each data key has a temporary `:lock` lease. Redis locks use random owner tokens;
release checks ownership. Publishing also atomically checks the owner token, so
an expired worker cannot overwrite a successor's response. Waiters have a finite
wait and receive a retryable lookup error when the owner remains busy.

Lease bounds derive from existing source budgets: WHOIS allows IANA and the
bounded RIR referral chain; PDNS covers its bounded request; IP/AS uses the
network timeout with headroom. They are operational bounds, not freshness TTLs.

Kvrocks errors fall back to the existing live-source lookup with bounded socket
operations. In this degraded mode cross-process deduplication is unavailable.
Source failures are still failures; they are not converted into successful empty
cache entries. Corrupt, expired or invalid-shaped cache records are misses.

Standalone consumers without backend configuration perform live lookups. No
credentials are inferred from another user's request.

## Capacity and operations

This cache is populated only by requested queries. WHOIS keeps its existing
response-size limit, and PDNS retains the export transport's 8 MiB response limit
and bounded stream. TTL bounds retention time, not total entry count: many distinct
IPs can still consume substantial storage. Assess Kvrocks disk/memory usage and
unique lookup volume before selecting longer lifetimes. There is no global entry
quota or claim of a measured production capacity limit.

Do not flush the database to clear enrichment caches: it also holds search and
coordination data. Normal expiration removes cache entries without intervention.
Rolling back the feature leaves these namespaced keys harmlessly expiring; SQL
snapshots and upstream data remain intact. No separate cache service is needed.

## Verification

`test/test_lookup_cache.py` exercises fixed expiry with a controllable clock,
concurrent callers, bounded waits, ownership changes, corrupt records, backend
outages, canonical queries, credential isolation and UI/report/export reuse.
Existing WHOIS permission, PDNS token, report filtering, target enrichment and
cross-theme UI tests cover the integration paths. Tests use disposable data and
mock upstream sources; they must not populate a production cache.
