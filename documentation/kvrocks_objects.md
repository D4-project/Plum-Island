# Kvrocks Objects

Plum Island uses Kvrocks as the fast search index for parsed scan documents.
The full scan document remains in Meilisearch; Kvrocks stores compact reverse indexes that map searchable values to document UIDs.

This page documents the current key model used by `webapp/app/utils/kvrocks.py` and `tools/index_kvrocks.py`.

## Document identity

Each parsed scan result has:

- `uid`: unique document identifier
- `ip`: host IP address
- `first_seen`: earliest known observation timestamp
- `last_seen`: latest known observation timestamp

Timestamps are stored as Unix epoch seconds.
Inputs may be epoch seconds, epoch milliseconds, or ISO timestamps; they are normalized before indexing.

## Core keys

| Key | Type | Value | Purpose |
| --- | ---- | ----- | ------- |
| `doc:{uid}` | hash | `ip`, `first_seen`, `last_seen` | Minimal per-document metadata used for rebuilds and date filtering |
| `uid:{uid}` | string | IP address | Fast UID to IP lookup |
| `all_uids` | set | UID | Count/list all indexed documents |
| `all_ips` | set | IP address | Count/list all indexed IPs |
| `ip:{ip}` | set | UID | Exact IP search |
| `first_seen_index` | sorted set | UID scored by `first_seen` | Date interval filtering |
| `last_seen_index` | sorted set | UID scored by `last_seen` | Date interval filtering |

Example:

```text
HSET doc:392f... ip 146.0.178.196 first_seen 1769069603 last_seen 1769069603
SET uid:392f... 146.0.178.196
SADD ip:146.0.178.196 392f...
ZADD first_seen_index 1769069603 392f...
ZADD last_seen_index 1769069603 392f...
```

## Network indexes

For every document IP, Plum indexes networks from `/16` to `/24`.

| Key | Type | Value | Purpose |
| --- | ---- | ----- | ------- |
| `net:{cidr}` | set | UID | Network search |

Example for `146.0.178.196`:

```text
net:146.0.0.0/16
net:146.0.128.0/17
net:146.0.128.0/18
net:146.0.160.0/19
net:146.0.176.0/20
net:146.0.176.0/21
net:146.0.176.0/22
net:146.0.178.0/23
net:146.0.178.0/24
```

Searches for masks outside `/16` to `/24` are resolved by selecting the closest indexed scope and filtering candidate UIDs by their `uid:{uid}` IP value.

## Generic field indexes

For each indexed field, Plum writes two sets:

| Key pattern | Type | Value | Purpose |
| ----------- | ---- | ----- | ------- |
| `{field}:{value}` | set | UID | Reverse index: find documents matching a value |
| `{field}s:{uid}` | set | value | Forward index: list values stored for one document |

Example:

```text
SADD http_title:vault 392f...
SADD http_titles:392f... vault
```

All generic indexed values are lowercased before they are written to Kvrocks.

Current generic fields:

| Field | Exact | Prefix/substring search | Notes |
| ----- | ----- | ----------------------- | ----- |
| `fqdn` | yes | yes | Fully qualified domain names found during parsing/enrichment |
| `fqdn_requested` | yes | yes | FQDN submitted to the scanner |
| `host` | yes | yes | Host/subdomain part |
| `domain` | yes | yes | Parsed registered domain |
| `domain_requested` | yes | yes | Requested domain |
| `tld` | yes | yes | Top-level domain |
| `tag` | yes | no | Computed tags, e.g. `soft:gitlab` |
| `port` | yes | no | Open port as string |
| `http_title` | yes | yes | HTML title |
| `http_favicon_path` | yes | yes | Favicon path/source |
| `http_favicon_mmhash` | yes | no | Favicon MurmurHash/mmh3 value |
| `http_favicon_md5` | yes | no | Favicon MD5 |
| `http_favicon_sha256` | yes | no | Favicon SHA-256 |
| `http_cookiename` | yes | yes | HTTP cookie names |
| `http_etag` | yes | yes | HTTP ETag values |
| `http_server` | yes | yes | HTTP Server header |
| `x509_issuer` | yes | yes | TLS issuer |
| `x509_md5` | yes | no | TLS certificate MD5 |
| `x509_sha1` | yes | no | TLS certificate SHA-1 |
| `x509_sha256` | yes | no | TLS certificate SHA-256 |
| `x509_subject` | yes | yes | TLS subject |
| `x509_san` | yes | yes | TLS SAN values |
| `banner` | yes | yes | Service banner |

## Tag-specific updates

Tag reindexing does not rebuild the whole Kvrocks index.
`tools/reindex_tagrule.py` uses `replace_field_values_batch("tag", docs)` to replace only:

```text
tag:{value}
tags:{uid}
```

For each UID:

1. read existing `tags:{uid}`
2. remove the UID from each old `tag:{value}`
3. delete `tags:{uid}`
4. write the new `tag:{value}` and `tags:{uid}` sets

The `--flush` option removes all keys matching:

```text
tag:*
tags:*
```

## Date filtering

The search UI applies date filtering by intersecting two sorted-set queries:

```text
last_seen_index >= from_ts
first_seen_index <= to_ts
```

This selects documents whose observation interval overlaps the requested search interval.

For last-seen-only filtering, Plum reads:

```text
ZRANGEBYSCORE last_seen_index from_ts to_ts
```

## Query behavior

Exact search reads:

```text
SMEMBERS {field}:{value}
```

Prefix and substring searches scan field keys:

```text
SCAN {field}:*
```

Then each candidate key is tested in Python:

- `field.bg:value` or `field.begin:value`: value starts with the requested text
- `field.lk:value` or `field.like:value`: value contains the requested text

The result set is built by intersecting fields inside one query group.
`OR` queries are evaluated as separate groups and unioned by the caller.

## Rebuild behavior

`tools/index_kvrocks.py --rebuild` deletes known Plum keys before reimporting dumped Meilisearch JSON documents.

Deleted fixed keys:

```text
all_ips
all_uids
first_seen_index
last_seen_index
```

Deleted pattern keys:

```text
doc:*
uid:*
ip:*
{field}:*
{field}s:*
```

for every generic field listed above.

Before deleting `doc:*`, the rebuild takes an in-memory snapshot of existing `first_seen` and `last_seen` values. During reimport, it preserves the earliest known `first_seen` and latest known `last_seen`.

`first_seen` is the only timestamp that cannot be fully reconstructed from the source Meilisearch/Nmap documents. The parser can recover `last_seen` from the scan document end time, but the first observation time is accumulated state in Kvrocks.

To persist that state outside Kvrocks before a rebuild, export it:

```bash
.venv/bin/python tools/first_seen_csv.py --export first_seen.csv
```

After rebuilding, restore it:

```bash
.venv/bin/python tools/first_seen_csv.py --import first_seen.csv
```

The export reads from `IN_KVROCKS_HOST` / `IN_KVROCKS_PORT`.
The import writes to `OUT_KVROCKS_HOST` / `OUT_KVROCKS_PORT`.
Import updates `doc:{uid}.first_seen` and `first_seen_index`; it does not overwrite `last_seen`.

## Dumping indexed values

Use `tools/dump_object.py` to list distinct indexed values for one field:

```bash
.venv/bin/python tools/dump_object.py http_title
.venv/bin/python tools/dump_object.py http_server
.venv/bin/python tools/dump_object.py tag
```

List dumpable fields:

```bash
.venv/bin/python tools/dump_object.py --list-dumpable
```

Output format:

```text
count,value
```

`count` is the cardinality of `{field}:{value}`, i.e. the number of UIDs currently attached to that value.

## Notes on the old store document

Older raw MONITOR captures are not a source of truth for the current schema.
Use this Markdown page for the maintained object model.
