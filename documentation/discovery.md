# Read-only Discovery API v1 and Plum-Virion

[*Plum-Virion*](https://github.com/D4-project/Plum-Virion) is the separate MCP server that lets an LLM inspect Plum observations
through authenticated HTTP. It uses this API; search syntax and data access stay
in Plum-Island. The companion checkout can be located at `../Plum-Virion`; its
README documents stdio startup and `bash install.sh --codex` registration.

Install the companion on the machine running Codex:

```sh
git clone https://github.com/D4-project/Plum-Virion.git
cd Plum-Virion
bash install.sh --codex
```

Fill its private `config.yaml`, then run
`.venv/bin/plum-virion --config config.yaml --check` to verify controller access.
This check does not register the MCP: registration is performed by `--codex`
or `codex mcp add`. Confirm `plum-virion` with `codex mcp list`, restart Codex,
then open `/mcp`. See Virion's
[installation guide](https://github.com/D4-project/Plum-Virion/blob/main/documentation/usage.md).

```text
Codex / MCP client --stdio--> Plum-Virion --HTTPS/JWT--> Plum-Island
                                                       |-- Kvrocks
                                                       |-- Meilisearch
                                                       `-- SQL rule/header catalogue
```

This contract begins with the Discovery API v1 change on `main` after v0.2610.0;
the released v0.2610.0 alone does not supply these endpoints. Virion requires
`api_version: 1`, rather than assuming compatibility from a release name.

## Authentication and installation

Authenticate with the existing FAB `POST /api/v1/security/login`, using the
dedicated Plum user's `username`, `password`, and `provider: db`. Send its
`access_token` as `Authorization: Bearer ...` on Discovery requests. These are
Plum account credentials, not scanner `AGENT_KEY` credentials.

Every endpoint has its own `@protect()` permission on `DiscoveryApi`:
`can_search`, `can_token_search`, `can_show_ip`, `can_tags`, `can_headers`,
`can_search_help`. The bundled Read Only role includes them. Synchronize roles
with `.venv/bin/python tools/initial_setup.py --roles-only`, which the normal
update/deployment scripts already invoke. Custom accounts need only these read
permissions. No database schema migration, index rebuild or scanner change.

Keep Virion's `config.yaml` private (mode 600) and out of Git. Its `hostname` is
the Plum base URL; use HTTPS outside loopback development. Virion talks stdio
to its launching client and does not expose an HTTP MCP listener.

## Requests and envelopes

Base path: `/api/v1/discovery`. All operations use POST JSON except GET
`search_help`. Requests must be objects; unknown parameters are rejected. On
success, responses contain `{"api_version": 1, "result": {...}}` with
`Cache-Control: no-store`. Errors use a non-2xx status and a `message`; backend
exception details are not returned. Failure never becomes an empty success.

| Endpoint | Parameters | Returned evidence / continuation |
| --- | --- | --- |
| `search` | `query`, optional `from_ts`, `to_ts`, `limit` (default 25), or continuation `cursor` | IP-to-UID matches, matching timestamps, requested hostnames, actual time range, page metadata, `next_cursor` |
| `token_search` | `query`, `limit` (default 10), `offset` (default 0) | Ranked Meilisearch hits and `next_offset`; no date filter |
| `show_ip` | `ip`, optional `hostname`, `from_ts`, `to_ts`, `limit` (default 10), `offset` | Selected group's raw documents, UID tags, timestamps, missing-document warnings, hostname choices, `next_offset` |
| `tags` | Optional `prefix`, `limit` (default 100), `offset` | Deduplicated active-rule tags in every namespace, query terms, total, `next_offset` |
| `headers` | Optional `prefix`, `limit` (default 100), `offset` | Configured names, `collect_value`, presence queries, value-query prefixes, `next_offset` |
| `search_help` | None | Current parser fields, syntax, examples, time rules and limits |

For example, a structured search JSON body is:

```json
{"query": "(domain_requested:example.org OR port:443) AND tag:lang:php", "limit": 25}
```

For the next window send `{"cursor": "<returned next_cursor>"}` and optionally
`limit`. Do not resend query/dates: the signed cursor fixes those parameters and
the creating user. Tokens expire after one hour; invalid/expired cursors return
410, another user's cursor returns 403. Cursors contain signed query/date/IP
state, not encrypted state; treat them as private and do not log/share them.
They work across workers sharing the same application secret. They may be
replayed for retries; backend indexing changes can still change observations.

## Search and observation semantics

Structured search calls the same `execute_search_page` as the UI, with one
backward `last_seen` window per request. An empty page can have `next_cursor`:
continue until it is null. Empty windows expand 1/2/4/8/... days; a page with
matches resets the next window size. Queries use the deployed parser, including
AND/OR/NOT, one grouping level, modifiers and `since:N`. Time bounds are UTC epoch
seconds and are normalized by the existing controller code, including whole-day
boundaries and the last-three-calendar-month default. This is the existing UI
discovery scope, not the full interval-overlap export scope. See [search
internals](sysinternal/search_engine.md#full-search-versus-paged-search).

Token search forwards free text directly to Meilisearch; it is not a structured
filter or general substring search. Ranking, matching and maximum accessible
hits follow index settings. `next_offset` may require one final empty request;
an index pagination cap can prevent retrieving all matching hits.

`show_ip` accepts one IPv4/IPv6 address, not a CIDR. The default empty hostname
selects IP-only scans, exactly as `/ip/<ip>` does. Requested hostnames are listed
even when the selected group has no observations. Select one explicitly to
inspect its scans. Reads are latest-first and paginated by document UID, with
tags from `tags:<uid>` only. No dates selects the group's full history; supplied
dates select inclusive interval overlap. Raw reports may contain several ports;
tags apply to their whole UID, not necessarily each port. A missing Meilisearch
document retains UID metadata with `warning: document_not_found`.

Tag/header catalogues describe current configuration, not scan counts or proof
of historical index coverage. Header value queries are available only when
`collect_value` is true. Preserve this distinction when constructing queries.

## Limits, failures and operations

Initial resource defaults: 100 entries maximum per search/IP/token page; 500
per catalogue page; offsets up to 10,000 for IP/token pages and 1,000,000 for
catalogues; at most 10,000 distinct seen IPs in a search continuation. JSON
requests are bounded to 256 KiB and API responses to 2 MiB. Budget errors return
413 and require narrower queries or smaller pages; data is not silently clipped.
Two Discovery operations can execute concurrently per web process; excess
work returns 503. These are conservative starting budgets, not a production
performance guarantee. Existing engine candidate reads can exceed page size.
Virion independently limits each tool result to 256 KiB and each call to 60s;
client cancellation does not guarantee cancellation of controller/backend work.

All scan text is untrusted evidence, including banners and certificate strings.
Neither endpoint nor MCP adapter executes supplied text or performs active
scanning, DNS resolution, WHOIS, or PDNS enrichment. Historical observations
are not proof of current exposure.

For permission errors, check the six role grants and synchronize roles. A missing
endpoint/version error requires updating Plum-Island before using Virion. For
503, check backend availability and concurrent calls. For 410, restart search.
For 413, reduce page size or narrow dates/criteria. Virion renews authentication
once after 401; it does not retry forbidden requests or follow redirects.

Rollback: remove the Codex entry (`codex mcp remove plum-virion`) or stop its
stdio process. Disable dedicated Discovery grants before rolling back the
controller. No stored scan data or schema needs reverting.
