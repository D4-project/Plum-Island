# Search

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

## Modifiers

Supported modifiers:

| Modifier | Alias | Meaning |
| -------- | ----- | ------- |
| `like` | `lk` | Substring match |
| `begin` | `bg` | Prefix match |

No modifier means exact match. like without any scope reducer may slowdown the research.

## Searchable fields

| Field | Modifiers | Description |
| ----- | --------- | ----------- |
| `ip` | | Host IP address |
| `net` | | CIDR network. Networks from `/16` to `/24` are indexed directly; other masks are resolved through the closest indexed scope and filtered |
| `fqdn` | `like`, `begin` | Fully qualified domain name found during enrichment |
| `fqdn_requested` | `like`, `begin` | FQDN originally submitted to the scanner |
| `domain_requested` | `like`, `begin` | Requested domain submitted to the scanner |
| `host` | `like`, `begin` | Hostname/subdomain part |
| `domain` | `like`, `begin` | DNS domain |
| `tld` | `like`, `begin` | Top-level domain |
| `tag` | | Computed document tag |
| `port` | | Open port |
| `http_title` | `like`, `begin` | HTML title |
| `http_cookiename` | `like`, `begin` | HTTP cookie name |
| `http_etag` | `like`, `begin` | HTTP ETag value |
| `http_server` | `like`, `begin` | HTTP Server header |
| `http_favicon_path` | `like`, `begin` | Favicon source path |
| `http_favicon_mmhash` | | Favicon MurmurHash value |
| `http_favicon_md5` | | Favicon MD5 hash |
| `http_favicon_sha256` | | Favicon SHA-256 hash |
| `banner` | `like`, `begin` | Service banner |
| `x509_issuer` | `like`, `begin` | TLS certificate issuer |
| `x509_md5` | | TLS certificate MD5 hash |
| `x509_sha1` | | TLS certificate SHA-1 hash |
| `x509_sha256` | | TLS certificate SHA-256 hash |
| `x509_subject` | `like`, `begin` | TLS certificate subject |
| `x509_san` | `like`, `begin` | TLS certificate subject alternative names |

## Date range

The structured search page applies a time range in addition to the query.

By default:

- start date is today minus 3 months
- start date is evaluated at `00:00:00`
- end date is evaluated at `23:59:59`

The time filter matches scan documents whose seen interval overlaps the selected range.

## Result loading

For responsiveness, the UI renders the first matching 100 IPs first.
Exports run on the full filtered result set, not only on the currently visible results.
