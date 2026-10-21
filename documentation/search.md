# Search

Contributor reference: [search engine internals and change contract](sysinternal/search_engine.md).

Plum Island stores parsed scan results in Kvrocks indexes. The main search UI uses these indexes to find matching scan documents and then loads full result details from Meilisearch when needed.

## InfoIP API

`GET /api/v1/infoip/<ip>` is a protected, Swagger-documented endpoint
that returns distinct open ports and their co-observed tags for indexed scan
reports of one public IPv4 or IPv6 address. CIDR ranges are rejected with `400`.
It reads the compact Kvrocks indexes.
Each port entry has `port`, `protocol` (`tcp` or `udp`), `tags`, `first_seen`, and `last_seen` fields. TCP and UDP on the same numbered port have separate entries. A tag is associated
with a port when both occurred in the same scan report; tags are computed for the whole report,
so they do not necessarily describe that port's service. Results are historical
observations within the selected window, not a claim that each port is open now.
`last_seen` is the latest UTC open-port observation in the selected window.
`first_seen` is the earliest UTC `first_seen` stored in Kvrocks among selected HSH
report IDs containing that port. It can be earlier than the requested window;
it does not imply the port stayed open continuously.
Only reports whose `last_seen` falls within that window are selected. A gap
between scans does not imply continuous openness; older observations of the same
report ID are not individually dated by this index.

The default window is the rolling last 30 days. Use `?days=90` or pass both
`?start=2026-09-01&stop=2026-09-30`. Dates use UTC; timezone-aware ISO datetimes
also work. `days` cannot be combined with `start`/`stop`. The earliest permitted
start is two calendar years before the request, and future stop times are rejected.
The API returns `404` when the IP has never been indexed and an empty `ports` list
when indexed reports exist but none have `last_seen` in the selected window.
Access uses the `can_get` permission on `InfoIpApi`; the default Read Only
role includes it after `tools/initial_setup.py --roles-only` synchronizes roles.

New reports index the protocol automatically. For older reports, InfoIP fetches
only missing protocols for the requested IP from Meilisearch and caches them in
Kvrocks. If Meilisearch is unavailable, `protocol` is `null`. To populate the
entire existing index in advance, run
`.venv/bin/python tools/backfill_port_protocol.py --dry-run`, then
`.venv/bin/python tools/backfill_port_protocol.py`. The command reads
Meilisearch via `IN_MEILI_*` and updates only the `port_protocol` index in
`OUT_KVROCKS_*` from `tools/config.yaml`.

## Query syntax

The small swap icon at the right of the keyword table header switches between
keyword help (the default) and a SQL rule-tag catalogue. Its five columns are
Proto, Type, Products, Vendors and Vulns. Tags come from active rules, are
deduplicated and sorted, and need not already occur in indexed scans. Reload the
page to refresh this catalogue after changing rules.

Every tag is clickable (also Enter/Space): for example `vendor:ovh` appends
`tag:vendor:ovh` to the current query. Keyword controls still append `keyword:`.
Neither action submits a search; the swap preserves the query, dates and results.
The return icon occupies the right side of the tags header. Other tag namespaces
remain searchable through the normal input/autocomplete. Empty columns display
`No tags`; a catalogue loading error leaves keyword help available.

Search terms use the form:

```text
field:value
field.modifier:value
```

Terms inside one group are combined with `AND` by default. Explicit `OR` can be used between groups.

### Parenthesized alternatives

Use one level of parentheses to apply a shared filter to several alternatives:

```text
(domain_requested:circl.lu OR net:185.194.93.0/24 OR net:185.194.94.0/24) AND tag:lang:php
```

This is equivalent to repeating `tag:lang:php` in each OR branch. AND binds more
tightly than OR. Multiple sibling groups work, for example
`(port:80 OR port:443) (http_server:nginx OR http_server:apache)`.
Nested groups, empty groups, unmatched parentheses and `NOT (group)` are rejected.
Quote literal parentheses in values: `http_title:"Welcome (portal)"`.
The same grammar applies to report validation and tag-rule queries.

Legacy flat queries retain their special IP/network behavior: `ip:A net:B`
unions those address scopes before applying other filters. Explicit groups are
Boolean operands: `(ip:A) (net:B)` intersects them. Use explicit OR for new
alternative address queries to make intent clear.

Search uses existing per-value Kvrocks set counts to choose selective positive
filters first and factors shared filters without expanding every combination.
Counters are ordering hints, not cached results: a zero count still requires
evaluating the predicate. No migration or index rebuild is required.
Substring/prefix estimates remain unknown; these still scan indexed field keys.
The planner's performance remains experimental pending representative deployment
benchmarks; a smaller seed does not avoid all large set reads.

Examples:

```text
domain.begin:"circl.lu" port:443 http_server.lk:nginx
```

```text
http_server.lk:nginx OR http_server.lk:apache
```

```text
fqdn_requested.lk:ttrenov.lu port:443
```

```text
http_header:cache-control http_headval:x-powered-by.lk:php
```

## Saving report queries

Report creation and editing validate the Search query before saving, including
inactive reports. Validation uses the existing structured-query parser without
contacting Meilisearch or Kvrocks. A syntactically valid query need not currently
match any scans, and valid tags need not already exist in a rule or index.

Errors appear on the query field and retain the submitted text; failed edits do
not replace the saved query or schedule. Use `ip:2001:db8::1` for an address and
`net:2001:db8::/48` for a network, not a bare IPv6 term. Network prefixes are not
guessed or corrected. Explicit AND/OR/NOT and implicit AND retain their meaning.

Save-time checks additionally reject empty values, dangling AND operators,
invalid IP/CIDR values and ports outside 0..65535. IP, net and port modifiers are
not accepted in reports. Tag syntax and canonicalization come from
`plum_antibodies.validate_tag`; accepted case/legacy-prefix variants are saved in
canonical form, with quoted values preserved. Existing parser rules for other
fields/modifiers remain unchanged. `since:` and `debug` remain supported; report
date bounds still determine the reporting interval.

No database migration or automatic rewrite of existing reports is performed.
Execution-time query checks remain in place for preview, manual and scheduled
reports. Operators must correct previously stored invalid queries themselves.

## Excluding results with NOT

Use `NOT` before a field term to exclude matching scan documents:

```text
tag:type:router AND NOT tag:vendor:mikrotik
tag:type:router NOT tag:vendor:mikrotik NOT tag:vendor:cisco
port:443 AND NOT http_server.lk:apache
```

`AND`, `OR` and `NOT` are case-insensitive. `AND` remains optional. `NOT`
applies only to the next term, including its supported exact/prefix/substring
modifier. Every OR path must have a positive term, possibly supplied outside a
parenthesized group; `NOT tag:vendor:mikrotik` alone is rejected.
Repeated `NOT NOT` and negating an entire group are not supported.
`NOT` cannot target `since:` or `debug` directives or legacy `.not`/`.nt` terms.
Quoted field values such as `http_title:"NOT AND OR"` remain literal values.

Exclusions are evaluated per document UID, before grouping by IP. A document
without the excluded value is retained, including when that field is absent.
If one IP has both an excluded scan and another matching scan, that IP can still
appear. Its asynchronously loaded tags cover a broader history and can therefore
include a tag excluded from the matching scans. This is not a whole-IP blacklist.

For example, `tag:type:router NOT tag:vendor:mikrotik OR tag:type:switch`
excludes MikroTik router scans in the first group; the second group still accepts
all switch scans. Exclusions also apply to full exports and expanded matching IP
history, with the existing date semantics of each path. No reindex is required.

## Modifiers

Supported modifiers:

| Modifier | Alias | Meaning |
| -------- | ----- | ------- |
| `like` | `lk` | Substring match |
| `begin` | `bg` | Prefix match |
| `not` | `nt` | Legacy suffixes with differing index-search/tag-rule behavior; use standalone `NOT` for exclusions |

No modifier means exact match. `like` without any scope reducer may slow down the research. `http_headval` supports only header-scoped `like` and `begin` modifiers.

## Searchable fields

| Field | Modifiers | Description |
| ----- | --------- | ----------- |
| `ip` | | Host IP address |
| `net` | | CIDR network. Networks from `/16` to `/24` are indexed directly; other masks are resolved through the closest indexed scope and filtered |
| `fqdn` | `like`, `begin` | Fully qualified domain name found during enrichment, including TLS certificate DNS SAN and subject CN names |
| `fqdn_requested` | `like`, `begin` | FQDN originally submitted to the scanner |
| `domain_requested` | `like`, `begin` | Requested domain submitted to the scanner |
| `host` | `like`, `begin` | Hostname/subdomain part |
| `domain` | `like`, `begin` | DNS domain found during enrichment, including normalized TLS certificate DNS SAN and subject CN names |
| `tld` | `like`, `begin` | Top-level domain |
| `tag` | | Computed document tag |
| `port` | | Open port |
| `http_title` | `like`, `begin` | HTML title |
| `http_cookiename` | `like`, `begin` | HTTP cookie name |
| `http_etag` | `like`, `begin` | HTTP ETag value |
| `http_header` | `like`, `begin` | Configured HTTP header name presence from `http-headers` NSE output |
| `http_headval` | header-scoped `like`, `begin` | Configured HTTP header value from `http-headers` NSE output |
| `http_server` | `like`, `begin` | HTTP Server header |
| `http_favicon_path` | `like`, `begin` | Favicon source path |
| `http_favicon_mmhash` | | Favicon MurmurHash value |
| `http_favicon_md5` | | Favicon MD5 hash |
| `http_favicon_sha256` | | Favicon SHA-256 hash |
| `banner` | `like`, `begin` | Service banner |
| `x509_issuer` | `like`, `begin` | Serialized TLS issuer DN when structured attributes are available |
| `x509_issuer_cn` | `like`, `begin` | TLS certificate issuer common name |
| `x509_md5` | | TLS certificate MD5 hash |
| `x509_sha1` | | TLS certificate SHA-1 hash |
| `x509_sha256` | | TLS certificate SHA-256 hash |
| `x509_subject` | `like`, `begin` | Serialized TLS subject DN when structured attributes are available |
| `x509_subject_cn` | `like`, `begin` | TLS certificate subject common name |
| `x509_san` | `like`, `begin` | TLS certificate subject alternative names |

Certificate-derived `fqdn`, `host`, and `domain` values require rebuilding/reimporting the Kvrocks index for scans collected before the parser change.

Certificate name compatibility: older indexes used `x509_issuer` and
`x509_subject` for commonName only. CN searches now use `x509_issuer_cn` and
`x509_subject_cn`; DN attribute searches can use, for example,
`x509_issuer.lk:"O=Example"`. Old SQL rules/report queries must be converted
before rebuilding fields. See the [certificate upgrade guide](../migration_full_cert.md).
DNs reflect available Nmap dictionaries, not canonical certificate identities;
where no DN can be constructed, preparation retains the parsed fallback value.

## HTTP header search

Only headers configured in `Config > Header Collection` are indexed. Active YAML
tag rules automatically add exact headers they reference to that collection;
manual entries remain supported. Header names and values are lowercased before
writing to Kvrocks. The `http_headval` autocomplete only suggests headers with
`Collect Value` enabled.

Header presence uses the normal field syntax:

```text
http_header:cache-control
http_header.lk:frame
http_header.bg:x-
```

Header values use a header-scoped syntax:

```text
http_headval:x-powered-by:php/8.2
http_headval:x-powered-by.lk:php
http_headval:x-powered-by.bg:php/8
http_headval:x-powered-by:"php 8.2"
```

The header name is exact in `http_headval` queries. `lk` and `bg` apply to the value part only.

## Date range

The structured search page applies a time range in addition to the query.

By default:

- start date is today minus 3 months
- start date is evaluated at `00:00:00`
- end date is evaluated at `23:59:59`

Initial IP discovery walks backward through windows of document `last_seen`.
Expanded IP history and full exports select documents whose seen interval overlaps
the selected range. These scopes differ for documents spanning the entire range.

## Result loading

The UI starts with a one-day window and renders each response immediately, even
when fewer than 100 IPs match. It widens empty windows and continues until 100 IPs
are displayed or the range is exhausted. Each response waits for its window's
query evaluation and metadata reads to finish.
Timestamp metadata is read only for matching UIDs belonging to each candidate IP;
unrelated historical documents are excluded before those reads. IP detail pages
retain history within the selected requested-hostname group.
Exports run on the full filtered result set, not only on the currently visible results.

The **Results of last scans** panel on a target detail page uses the target's
oldest displayed scan timestamp through the current time. It renders IPs first,
then retrieves their tag badges asynchronously in the same 200-IP batches as
the structured search. Selecting an IP opens its IP detail page; its info icon
expands the matching scan results.

## IP detail web links

The Requested Hostname selector loads only that hostname's reports; opening a
`/ip/<ip>?hostname=example.org` link selects that group on the server before
fetching full documents. Without `hostname`, the page shows IP-only reports.
All hostname choices come from the compact Kvrocks index, not from loading all
Meilisearch documents. An unknown hostname returns 404 rather than displaying
unrelated reports. Incomplete hostname indexes need reindexing; the view does
not automatically rebuild them or fetch every full document as a fallback.

Switching groups updates the shareable URL without reloading the page. Already
loaded groups remain in page memory, including their selected observations;
Back/Forward and revisiting a hostname reuse them without another request.
Late replies can populate the cache but never overwrite a newer selection.
Loading failures offer Retry. Reload the page to refresh cached scan data.
Scan/port counts, tags and first/last-seen metadata follow the selected group;
the virtual-host count covers all hostname choices. WHOIS and Passive DNS remain
independent. No browser-persistent scan cache is created.

The Informations tab starts IP enrichment and Passive DNS only on its first
opening. Both requests run independently with centered loading spinners, so IP
information can appear while Passive DNS is still loading. Returning to the tab
reuses those results. IP and AS information appear side by side on wide screens,
stacking on small screens.

On `/ip/<ip>`, a port's open-web-service button appears when the active scan
observation has the indexed tag `proto:http`. Service names alone do not enable
the button. The link uses HTTPS when that port reports an SSL/TLS tunnel, a secure
service name (`https`, `https-alt`, `ssl`, `tls`, `ssl/...` or `tls/...`), or an
`ssl-cert` script; otherwise it uses HTTP.

The destination keeps the actual scanned port: HTTP on 8080 opens
`http://IP:8080`, HTTPS on 8443 opens `https://IP:8443`. Default HTTP/80 and
HTTPS/443 ports are omitted from the URL. The Requested Hostname selection is
used as the destination when selected, otherwise the IP is used. Switching a
timeline selection or hostname updates the button for the newly active observation.

Each port's grey header includes an interactive observation timeline. A point
marks a result's `last_seen`; a line extends from `first_seen` when the dates
differ. A vertical tick extending equally above and below the horizontal line
marks `first_seen` for a period with different start/end dates; hovering the tick
shows that start date. Equal dates produce only a point, without a tick.
Each port's observation count follows the selected hostname (or IP-only filter).
These periods do not prove continuous service availability. All ports
share the earliest/latest observation bounds for the selected requested hostname
(or IP-only results). Changing the filter recomputes these bounds; hidden
hostnames do not stretch the timeline. All points and periods stay on one line,
and a single distinct date gets a centered 150-day window (about five months).
Points may be close together or overlap. The latest matching result is selected
when a group is first loaded; revisiting a cached group preserves its selection.
Click a point, or focus it and press Enter/Space, to show its report.
Points enlarge on hover/focus; the hover tooltip shows only the exact UTC
`last_seen` date. Timeline tooltips use `YYYY-MM-DD HH:mm:ss` in UTC, without
milliseconds. Results without usable
dates remain available through separate buttons. No extra requests are made by
the timeline; hostname changes fetch uncached groups on demand.

## Passive DNS timeline

On the IP detail **Informations** tab, Passive DNS uses the same timeline
renderer in a single panel. Each record has a `Rdata (RRType)` label and a
`time_first` to `time_last` line, with a point at the end. All PDNS rows share
one date axis at the top and a continuous vertical grid. Their own time scale
is independent of scan ports and the requested-hostname
filter. Equal dates show only a point; a single distinct date uses the centered
150-day window. Hover dates use the same UTC format. RRName and count remain
available in the label tooltip. The most recently observed record is highlighted
initially; clicking a label or point highlights that row. Missing dates remain
explicit rather than being replaced by the current date.

### Active DNS verification

The heading keeps **Passive DNS** on the left and a refresh-icon **Active DNS**
button on the right (tooltip: **Resolve**). Click it to check whether the displayed
IPv4 still appears in the current A answers for each eligible PDNS hostname.
No active DNS requests run merely by opening the tab. Names are deduplicated;
non-A records and IPv6 views are not actively verified by this control.
The progress counter occupies the top-left cell of the grey timeline panel,
alongside the date axis. Its space stays reserved even before the first check.

Checks run asynchronously through the server's configured DNS resolver using
`dnspython`. Successful matches add a **red point at the verification time**, with a dashed connector
from the existing last-seen point, on the same row. The common PDNS scale expands
to include verification timestamps; port timelines are unaffected. Hover shows
the UTC verification time. The connector does **not** prove uninterrupted
resolution between the historical observation and the live check.

Historical points and stored `time_first`/`time_last` remain unchanged. Without a
known last-seen date, a matching result gets a point but no invented connector.
Results are kept only in page memory, not written to SQL, Kvrocks, Meilisearch or
CIRCL. Repeating a check replaces the previous live overlay.

Each row distinguishes a match, different address, NXDOMAIN/no A answer, timeout
and resolver failure. Resolver errors are not evidence that a name has stopped
resolving. Busy/error rows can be retried with the button. Empty or disabled PDNS
and records without a usable hostname/IP association leave the button disabled.

Operational defaults are four browser requests and four active DNS lookups per
web process, a five-second DNS lifetime, and a fifteen-second browser request
deadline. These are conservative bounds, not measured production throughput
targets. They are defined in `utils/pdns_resolve.py` and `static/js/ip_pdns_resolve.js`.
Resolution uses absolute hostnames without local search suffixes and does not
contact the returned IPs. Results reflect the backend resolver's view and cache,
not necessarily every public resolver or authoritative server.

The new route requires `can_resolve_passive_dns` on `IPDetailView`, plus CSRF
validation and a signed authorization for a hostname from the displayed PDNS.
Authorizations expire after one hour; reload the page if the row tooltip reports
an expired token. Install updated `requirements.txt` and synchronize roles with
`tools/initial_setup.py --roles-only` (also run by the update script and Docker
entrypoint). Custom roles need the new permission explicitly; no SQL schema
migration is required. Removing that permission disables access for that role
without touching stored history.

## Performance diagnostics

Add the standalone keyword `debug` to a structured search:

```text
http_server.lk:apache debug
http_server.lk:nginx since:3 debug
```

After each page response, including empty pages, open **Performance** below the
search controls. **Download JSON** saves a report for troubleshooting. The report
includes backend stage times, Kvrocks command counts and reply sizes in items,
window/matching/IP counts, browser request times and time to first results inserted
into the page. Keep the query and selected dates separately when comparing runs.

The `planner` object records planning time (including count reads), estimated
candidate counts, anonymous predicate IDs and evaluation order, scope/result
sizes, and reused predicates. `null` estimates mean unknown. Counter reads appear
under Kvrocks `SCARD` totals even when diagnostics are disabled; enabling `debug`
does not add search commands. Counts are global per indexed value, not per date
window. HTTP-header groups retain their legacy evaluation path and are marked
`legacy` in planner steps. Their internal seed is not reordered.

`debug` is case-insensitive and does not change filters, dates, ordering or
pagination. `http_title:debug` still searches for that value; `debug` alone is not a
valid search. Exports and IP history expansion ignore the directive while retaining
the same criteria. Tag-rule queries do not accept it.

This measures interactive search pages only. It does not measure initial page
loading, asynchronous tags/history, Meilisearch document loading or export jobs.
There is no live backend progress inside a pending page request. Client-call times
include waiting, transfer and decoding; they are not Kvrocks CPU time. Counts are
items, not bytes or distinct UIDs. Instrumentation adds overhead when enabled;
compare several runs rather than treating one report as a benchmark.

The browser retains the latest 100 detailed responses plus cumulative request/server
times and response count until a new search or reload. No query text, keys, IPs,
UIDs or document contents are included in diagnostics.
