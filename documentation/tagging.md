# Tagging

Plum Island can apply computed tags to scan documents through tag rules.
A tag rule is a named search query with one or more tags attached. When a scan document matches the query, the tags are written back to the document index.

## YAML format

Tag rules are stored under `webapp/tags/` as YAML files.
The filename, with `.yaml`, is the rule name.

Example:

```yaml
description: HashiCorp Vault
query: http_favicon_mmhash:747250914 AND http_title.bg:Vault
tags:
- product:hashicorp-vault
- vendor:hashicorp
version: 20260428T170756Z
```

Fields:

| Field | Required | Description |
| ----- | -------- | ----------- |
| `description` | yes | Human-readable rule description |
| `query` | yes | Structured search query using the same syntax as the search UI |
| `tags` | yes | List of tags to apply |
| `version` | recommended | Rule timestamp used during imports |

## Version policy

`tools/tag_mgmt.py import` imports YAML rules into the SQLite database.

Conflict policy:

- New YAML rules are inserted.
- Existing DB rules are replaced only when the YAML version is newer than the DB rule timestamp.
- A YAML file without `version` does not replace an existing DB rule.

This keeps local DB edits unless the YAML file carries a newer version.

## Import commands

Import every YAML rule from `webapp/tags/`:

```bash
.venv/bin/python tools/tag_mgmt.py import --all
```

Import one YAML file only:

```bash
.venv/bin/python tools/tag_mgmt.py import --tags-file webapp/tags/hashicorp_vault.yaml
```

Import the YAML rule matching an existing DB tag rule id:

```bash
.venv/bin/python tools/tag_mgmt.py import --id 42
```

Preview changes without writing:

```bash
.venv/bin/python tools/tag_mgmt.py import --all --dry-run
```

Flush all tag rules from SQLite:

```bash
.venv/bin/python tools/tag_mgmt.py delete --all
```

Flush preview:

```bash
.venv/bin/python tools/tag_mgmt.py delete --all --dry-run
```

## Web UI

The Tag Rules UI supports:

- creating and editing rules
- batch deletion through checkboxes
- compact tag display in the list view
- rule descriptions on rule-name hover
- exporting YAML files to disk
- downloading all rule YAML files as a ZIP archive

## Reindexing

After rules change, tags can be recomputed with `tools/tag_mgmt.py reindex`.

List complete tags currently present in Kvrocks:

```bash
.venv/bin/python tools/tag_mgmt.py list-tags
```

The command prints stored tag values such as:

```text
product:gitlab
vendor:gitlab
type:firewall
proto:http
```

## Tag naming

Stored YAML and SQLite tag values use the normalized `<namespace>:<value>` format.
Common namespaces:

- `vendor:*` for vendor, project, or organization names
- `product:*` for software, product, service, or device family names
- `type:*` for broad asset families or roles, such as `firewall`, `router`, `cms`, `vpn`, or `webmail`
- `proto:*` for protocols or protocol families, such as `http`, `ssh`, `ftp`, `sip`, `telnet`, `bgp`, or `icy`
- `vuln:*` for vulnerability-oriented classifications

Do not prefix stored YAML tags with `tag:`. `tag:` is the search field and Kvrocks key prefix, so adding it to YAML would create duplicated keys such as `tag:tag:proto:bgp`.

Do not use the old `soft:*` or `hard:*` prefixes in new rules. They were replaced by `product:*`, `vendor:*`, and `type:*`.

Protocol tags must use `proto:*` in YAML. Search for them as `tag:proto:*` in the UI.

Favicon rules usually use `product:<product>` and `vendor:<vendor>`.
Add `type:*` when the favicon identifies an asset family rather than only a product.

Protocol-only rules should tag with `proto:*` and avoid product/vendor tags unless the signal identifies a specific implementation.
For example, an HTTP banner prefix rule should use `proto:http`; a HashiCorp Vault favicon rule should use `product:hashicorp-vault` and `vendor:hashicorp`.

# Source of information used.

To build, and craft some of the detection rules, We based our knowledge on various open source;

- https://github.com/OWASP/www-project-secure-headers
- https://github.com/nmap/nmap/blob/9965fef7743c9f67dfe310b8e42c83cf170fa434/nselib/data/favicon-db
- https://github.com/sansatart/scrapts/blob/master/shodan-favicon-hashes.csv

Many thank's to these creators
