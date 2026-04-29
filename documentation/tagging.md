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
- soft:hashicorp-vault
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
- Existing DB rules are replaced only when the YAML version is older than the DB rule timestamp.
- A YAML file without `version` is considered older than any DB rule.

This preserves the oldest rule definition when multiple copies exist.

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
soft:gitlab
hard:gpon-gateway
```

## Tag naming

Common tag prefixes:

- `soft:*` for software or product identification
- `hard:*` for hardware or device family identification
- `vuln:*` for vulnerability-oriented classifications

Favicon rules usually use `soft:<product>` or `hard:<device>` depending on what the favicon identifies.
