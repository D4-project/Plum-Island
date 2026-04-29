<div align="center">
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_logo.png" style="width:25%;" />

<h1>Proactive Land Uncovering & Monitoring</h1>
  <img alt="d4-Plum-Island overview" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_overview.png" />
</div>

<p align="center"><em>Beta version</em></p>

## Description

Plum Island is an orchestrator for proactive surface-exposure discovery.
It assigns scan jobs to distributed agents, collects their results, stores scan history, and makes the collected data searchable through indexed technical indicators.

The project is designed for repeated monitoring rather than one-shot scans: targets can be linked to scan profiles, jobs are queued by priority, results are kept over time, and reports can summarize what changed during a period.

## Main features

- Distributed scan orchestration with agents and server-side job queues.
- Target and scan profile management.
- Per-profile scan tracking for each target.
- Indexed search over IPs, networks, ports, DNS names, HTTP metadata, favicons, TLS certificates, banners, and computed tags.
- Structured query syntax with exact, prefix, substring, `AND`, `OR`, and date-range filtering.
- Tag rules that automatically add tags to matching scan documents.
- Favicon-based tagging using MD5, SHA-256, and mmhash indicators.
- Scheduled Markdown reports from the same search syntax used by the UI.
- CSV/JSON export workflows for search results.

## Search options

The search index supports fields such as:

- `ip`, `net`, `port`
- `fqdn`, `fqdn_requested`, `domain`, `domain_requested`, `host`, `tld`
- `http_title`, `http_cookiename`, `http_etag`, `http_server`
- `http_favicon_path`, `http_favicon_mmhash`, `http_favicon_md5`, `http_favicon_sha256`
- `banner`
- `x509_issuer`, `x509_subject`, `x509_san`, `x509_md5`, `x509_sha1`, `x509_sha256`
- `tag`

Example:

```text
domain.begin:"circl.lu" port:443 http_server.lk:nginx
```

See [Search documentation](documentation/search.md) for the full field list, modifiers, examples, and date-range behavior.

## Tagging

Tag rules are stored as YAML definitions and can also be managed from the web UI.
Each rule contains a description, a search query, a list of tags, and a version timestamp.

Example:

```yaml
description: HashiCorp Vault
query: http_favicon_mmhash:747250914 AND http_title.bg:Vault
tags:
- soft:hashicorp-vault
version: 20260428T170756Z
```

See [Tagging documentation](documentation/tagging.md) for YAML format, import/export tooling, version handling, and reindexing.

## Reports

Reports use the same structured search syntax as the interactive search page.
They generate Markdown summaries for a reporting interval and can be previewed, run manually, or sent on a schedule.

See [Reports documentation](documentation/reports.md) for report configuration, interval handling, Markdown content, and SMTP delivery.

## Documentation

- [Installation](documentation/installation.md)
- [Search](documentation/search.md)
- [Tagging](documentation/tagging.md)
- [Reports](documentation/reports.md)
- [Scan profiles, scheduling, and priority](documentation/scanning.md)
- [Tools](documentation/tools.md)
- [Kvrocks objects](documentation/kvrocks_objects.md)

## Technical requirements

- Python 3.10+
- Flask AppBuilder 4.8
- Meilisearch 1.22.2+
- Kvrocks unstable build 8f04af34+, with RocksDB 10.4.2+
