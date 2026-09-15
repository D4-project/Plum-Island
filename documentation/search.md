# Search

Contributor reference: [search engine internals and change contract](sysinternal/search_engine.md).

Plum Island stores parsed scan results in Kvrocks indexes. The main search UI uses these indexes to find matching scan documents and then loads full result details from Meilisearch when needed.

## Query syntax

Search terms use the form:

```text
field:value
field.modifier:value
```

Terms inside one group are combined with `AND` by default. Explicit `OR` can be used between groups.

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

## Excluding results with NOT

Use `NOT` before a field term to exclude matching scan documents:

```text
tag:type:router AND NOT tag:vendor:mikrotik
tag:type:router NOT tag:vendor:mikrotik NOT tag:vendor:cisco
port:443 AND NOT http_server.lk:apache
```

`AND`, `OR` and `NOT` are case-insensitive. `AND` remains optional. `NOT`
applies only to the next term, including its supported exact/prefix/substring
modifier. Each OR group must contain a positive term; `NOT tag:vendor:mikrotik`
alone is rejected. Parenthesized groups and repeated `NOT NOT` are not supported.
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
| `x509_issuer` | `like`, `begin` | TLS certificate issuer |
| `x509_issuer_cn` | `like`, `begin` | TLS certificate issuer common name |
| `x509_md5` | | TLS certificate MD5 hash |
| `x509_sha1` | | TLS certificate SHA-1 hash |
| `x509_sha256` | | TLS certificate SHA-256 hash |
| `x509_subject` | `like`, `begin` | TLS certificate subject |
| `x509_subject_cn` | `like`, `begin` | TLS certificate subject common name |
| `x509_san` | `like`, `begin` | TLS certificate subject alternative names |

Certificate-derived `fqdn`, `host`, and `domain` values require rebuilding/reimporting the Kvrocks index for scans collected before the parser change.

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
retain their full history.
Exports run on the full filtered result set, not only on the currently visible results.

The **Results of last scans** panel on a target detail page uses the target's
oldest displayed scan timestamp through the current time. It renders IPs first,
then retrieves their tag badges asynchronously in the same 200-IP batches as
the structured search. Selecting an IP opens its IP detail page; its info icon
expands the matching scan results.

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
