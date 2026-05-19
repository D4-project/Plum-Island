# Tagging

Plum Island can apply computed tags to scan documents through tag rules.
A tag rule is a named search query with one or more tags attached. When a scan document matches the query, the tags are written back to the document index.

## YAML format

Tag rules are stored under `webapp/tags/` as YAML files.
The filename, without `.yaml`, is the rule name.

Example:

```yaml
description: HashiCorp Vault
query: http_favicon_mmhash:747250914 AND http_title.bg:Vault
tags:
- tag:product:hashicorp-vault
- tag:vendor:hashicorp
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

`tools/import_tags.py` imports YAML rules into the SQLite database.

Conflict policy:

- New YAML rules are inserted.
- Existing DB rules are replaced only when the YAML version is newer than the DB rule timestamp.
- A YAML file without `version` does not replace an existing DB rule.

This keeps local DB edits unless the YAML file carries a newer version.

## Import commands

Import every YAML rule from `webapp/tags/`:

```bash
.venv/bin/python tools/import_tags.py
```

Import one YAML file only:

```bash
.venv/bin/python tools/import_tags.py --tags-file webapp/tags/hashicorp_vault.yaml
```

Preview changes without writing:

```bash
.venv/bin/python tools/import_tags.py --dry-run
```

Flush all tag rules from SQLite:

```bash
.venv/bin/python tools/import_tags.py --flush_db
```

Flush preview:

```bash
.venv/bin/python tools/import_tags.py --flush_db --dry-run
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

After rules change, tags can be recomputed with `tools/reindex_tagrule.py`.

List complete tags currently present in Kvrocks:

```bash
.venv/bin/python tools/reindex_tagrule.py --list_tags
```

The command prints tag keys such as:

```text
tag:product:gitlab
tag:vendor:gitlab
tag:type:firewall
tag:proto:http
```

## Tag naming

Tags use the normalized `tag:<namespace>:<value>` format.
Common namespaces:

- `tag:vendor:*` for vendor, project, or organization names
- `tag:product:*` for software, product, service, or device family names
- `tag:type:*` for broad asset families or roles, such as `firewall`, `router`, `cms`, `vpn`, or `webmail`
- `tag:proto:*` for protocols or protocol families, such as `http`, `ssh`, `ftp`, `sip`, `telnet`, `bgp`, or `icy`
- `vuln:*` for vulnerability-oriented classifications

Do not use the old `soft:*` or `hard:*` prefixes in new rules. They were replaced by `tag:product:*`, `tag:vendor:*`, and `tag:type:*`.

Do not use bare `proto:*` in new rules. Protocol tags must use `tag:proto:*`.

Favicon rules usually use `tag:product:<product>` and `tag:vendor:<vendor>`.
Add `tag:type:*` when the favicon identifies an asset family rather than only a product.

Protocol-only rules should tag with `tag:proto:*` and avoid product/vendor tags unless the signal identifies a specific implementation.
For example, an HTTP banner prefix rule should use `tag:proto:http`; a HashiCorp Vault favicon rule should use `tag:product:hashicorp-vault` and `tag:vendor:hashicorp`.

# Source of information used.

To build, and craft the detection rules, We based our knowledge on various open source;

- https://github.com/OWASP/www-project-secure-headers
- https://github.com/nmap/nmap/blob/9965fef7743c9f67dfe310b8e42c83cf170fa434/nselib/data/favicon-db
- https://github.com/sansatart/scrapts/blob/master/shodan-favicon-hashes.csv

Many thank's to these creators
