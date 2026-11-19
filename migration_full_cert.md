# Certificate search upgrade: common names and distinguished names

This operational guide describes the existing implementation, not a proposal to
change the parser. It replaces the earlier design checklist. No production
migration or live-backend validation is implied by this document.

## Current contract

Raw Meilisearch JSON is unchanged. `parse_json()` retains historical commonName
values in `x509_issuer` and `x509_subject`. Index writers subsequently call
`prepare_kvrocks_document(raw_doc, parsed_doc, tag_rules=...)` on a copy:

| Indexed field | Value when structured certificate data is available |
| --- | --- |
| `x509_issuer_cn` | Issuer commonName, without a `CN=` prefix |
| `x509_subject_cn` | Subject commonName, without a `CN=` prefix |
| `x509_issuer` | Serialized issuer attributes, e.g. `CN=Example CA, O=Example, C=LU` |
| `x509_subject` | Serialized subject attributes |

Serialization uses CN, OU, O, L, ST, C order followed by remaining attribute names
in lexical order. List values retain input order. Separators are escaped; CR/LF,
initial `#`, and first/last spaces receive dedicated escaping. This is a search
representation of Nmap dictionaries, not a canonical ASN.1 identity or exact
reconstruction of the original DN. PEM-only sources are not decoded here.
Unexpected input types are not comprehensively validated; inspect parser errors.

If no DN is constructed, preparation retains the old parsed value rather than
inventing attributes. Missing source attributes cannot be recovered from a CN.
Kvrocks lowercases indexed values. When rules are supplied, preparation recomputes
tags against the enriched copy. IDs, timestamps, SANs and raw certificates are
not changed by this certificate migration.

## Compatibility change

Existing CN-based queries must use explicit fields after rebuilding:

```text
x509_issuer.lk:example -> x509_issuer_cn.lk:example
x509_subject.bg:device -> x509_subject_cn.bg:device
```

New DN searches intentionally keep the original names, for example
`x509_issuer.lk:"O=Example"`. There is no alias distinguishing old CN queries from
new DN queries. Review/convert existing SQLite rule and report queries before
using the enriched index. External saved queries/bookmarks need separate updates.

## Existing tool behavior and limitations

`tools/migrate_full_cert.py` requires `--dry-run` or `--apply` and accepts
`--db` and `--yaml-dir`. It does not import Flask or start the scheduler.

- SQL conversion visits `tagrules.query` and `reports.query`, active and inactive.
  Other row fields are not updated. Legacy field names and supported suffixes
  outside quoted values are renamed; this is not a complete query validator.
- Dry-run prints affected YAML paths and SQL row IDs, not a full query diff.
  Inspect old/new query text separately before accepting conversion.
- SQL updates and the `plum_migrations` marker `full_cert_fields_v1` are committed
  together. A present marker prevents another conversion, protecting later DN
  queries. Do not delete the marker to rerun.
- A missing DB path is rejected, but missing query tables are skipped. Successful
  exit does not prove the correct application DB was selected; verify its tables.
- YAML discovery is non-recursive `*.yaml` in `--yaml-dir`. The default is
  `webapp/tags`, while bundled rules live in `webapp/tags/tags`. YAML edits and
  the SQLite commit are not one atomic operation. YAML rewriting is broader than
  SQL quote handling and does not provide complete semantic validation.

Use the SQL-only procedure below with an empty YAML directory for existing
deployments. Do not run YAML-writing mode against the Antibodies submodule as
part of a routine upgrade. Bundled rules must already have the intended CN/DN
semantics; review customized rules independently.

## Upgrade procedure

### 1. Freeze writers and verify backups

Validate on a disposable copy first. Stop application workers, scheduler, scan
ingestion and indexing/tag-reindex tools; pause agents. Wait for already submitted
Meilisearch tasks to finish. Keep both search services accessible to tools.
Back up SQLite including WAL state, Kvrocks, raw JSON, configuration, Meilisearch,
and previous Git/submodule revisions.

Record UID counts/sets, timestamp bounds, tags and reference queries. Recover
missing Meilisearch documents before rebuilding, following
[index recovery](documentation/recovery-tools.md). Counts alone do not prove
retained documents contain structured certificate attributes.

### 2. Deploy code and convert SQL queries

Apply numbered SQL migrations first, without restarting writers. Use the actual
application DB path below and confirm it contains `tagrules` and `reports`.
Review whether old fields really mean CNs: do not mechanically convert an instance
already using intentional DN queries without a migration marker.

From the repository root, in the same shell for both commands:

```bash
cert_yaml_empty=$(mktemp -d /tmp/plum-cert-yaml-empty.XXXXXX)
.venv/bin/python tools/migrate_full_cert.py \
  --db webapp/app.db --yaml-dir "$cert_yaml_empty" --dry-run

# Inspect affected rows and approve conversion before applying.
.venv/bin/python tools/migrate_full_cert.py \
  --db webapp/app.db --yaml-dir "$cert_yaml_empty" --apply
rmdir "$cert_yaml_empty"
```

No YAML files are edited in this mode. Backups are operator-managed; no backup
argument is required. Verify the marker and converted query text, then validate
rules/report queries with their normal validators. The tool does not perform
those application-level checks. `import --all` is not a substitute: YAML version
policy can overwrite or skip locally customized rules.

Before refreshing seeds, ensure deployed Antibodies queries already use intended
CN/DN fields. Preserve local rule customizations rather than silently replacing
them with bundled versions.

### 3. Rebuild fields and tags

Verify `IN_MEILI_*` and `OUT_KVROCKS_*` in `tools/config.yaml` target the intended
backends; recovery tools may use `webapp/config.py` instead. Keep writers stopped:

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili --retag
```

This recreates search indexes while retaining `doc:{uid}` hashes to merge known
timestamps for retained UIDs. Raw Meilisearch documents feed enriched fields and
active SQL rule evaluation. Tag-only `tools/tag_mgmt.py reindex --allrules`
cannot reconstruct missing certificate fields.

If the version-specific upgrade already performs a complete replacement import
through current `reimport_port_dump.py`, that import prepares the same fields and
recomputes tags. Convert SQL queries before that import; a second rebuild is not
needed solely for certificates. Replacement history handling differs from ordinary
rebuilds: follow the applicable version-specific guide.

### 4. Validate before resuming

- Check final error counters and CN/DN forward/reverse indexes; zero exit alone
  does not prove complete migration.
- Compare UID sets and observation dates with the baseline; explain omissions.
- Test exact/prefix/substring CN queries and DN attributes, including absent CNs,
  escaped commas and custom rule/report queries.
- Verify tags, IP detail and representative report previews. Inspect sources
  without a constructed DN instead of claiming complete historical coverage.
- Verify a second SQL-only invocation reports the marker and leaves intentional
  new DN queries unchanged.

Resume ingestion only after validation. This guide does not certify that any
particular production index was migrated successfully.

## Failure and rollback

An interrupted rebuild leaves a partial index. Keep searches/reports and writers
in maintenance; fix the cause and rebuild from the unchanged complete source, or
restore backups. A full rebuild has no resumable cursor.

Rollback requires matching previous code, SQLite (including marker state), rules
and Kvrocks snapshot. Restore Meilisearch if another upgrade step changed it.
Account for writes since the backup before restoring. Do not combine old CN-only
code with a new DN index or blindly reverse all field names. SQL/YAML/backend
changes are not one transaction.

## Maintainer verification

Relevant tests: `test/test_migrate_full_cert.py` and
`test/test_result_parser_full_cert_index.py`. They use synthetic data, not a live
migration. Run the repository suite and a representative disposable backend round
trip before production rollout. Keep future requirements separate from this
description of implemented behavior.
