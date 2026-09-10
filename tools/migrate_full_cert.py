#!/usr/bin/env python3
"""Migrate certificate search queries to the explicit commonName fields."""

import argparse
from datetime import datetime, timezone
import re
import sqlite3
from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_YAML_DIR = BASE_DIR / "webapp" / "tags"
DEFAULT_DB = BASE_DIR / "webapp" / "app.db"
CERTIFICATE_FIELD_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])x509_(issuer|subject)"
    r"(?=(?:\.(?:lk|like|bg|begin|not|nt))?:)"
)
MIGRATION_TABLE = "plum_migrations"
MIGRATION_NAME = "full_cert_fields_v1"


def rewrite_certificate_query(query):
    """Rename old CN-backed fields outside quoted query values."""
    text = str(query or "")
    output = []
    quote = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if quote and char == "\\":
            output.append(char)
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            output.append(char)
            index += 1
            continue
        if quote is None:
            match = CERTIFICATE_FIELD_RE.match(text, index)
            if match:
                output.append(f"x509_{match.group(1)}_cn")
                index = match.end()
                continue
        output.append(char)
        index += 1
    return "".join(output)


def current_version():
    """Return a UTC YAML version timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def migrate_yaml_text(text, version):
    """Rewrite one YAML document while preserving its surrounding formatting."""
    payload = yaml.safe_load(text) or {}
    if not isinstance(payload, dict):
        raise ValueError("tag YAML must contain a mapping")
    old_query = str(payload.get("query") or "")
    new_query = rewrite_certificate_query(old_query)
    if new_query == old_query:
        return text, False

    lines = text.splitlines(keepends=True)
    query_start = None
    query_end = None
    for line_index, line in enumerate(lines):
        if re.match(r"^query:\s*", line):
            query_start = line_index
            query_end = line_index + 1
            while query_end < len(lines):
                if lines[query_end].strip() and not lines[query_end].startswith((" ", "\t")):
                    break
                query_end += 1
            break
    if query_start is None:
        raise ValueError("tag YAML has no query field")

    block = "".join(lines[query_start:query_end])
    # The YAML scalar can wrap the entire query in single quotes. At this
    # layer we are already inside the query field, so rewrite its field tokens
    # regardless of the YAML scalar quoting. Values are parsed and validated
    # separately above; certificate field names are not valid free-text values
    # in the bundled rules.
    rewritten_block = CERTIFICATE_FIELD_RE.sub(
        lambda match: f"x509_{match.group(1)}_cn", block
    )
    lines[query_start:query_end] = [rewritten_block]

    result = "".join(lines)
    result = re.sub(
        r"(?m)^version:\s*[^\r\n]+$",
        f"version: {version}",
        result,
        count=1,
    )
    return result, True


def iter_yaml_migrations(tags_dir, version):
    """Yield changed YAML paths and their migrated contents."""
    for path in sorted(Path(tags_dir).glob("*.yaml")):
        original = path.read_text(encoding="utf-8")
        migrated, changed = migrate_yaml_text(original, version)
        if changed:
            candidate = yaml.safe_load(migrated)
            if not isinstance(candidate, dict) or not candidate.get("query"):
                raise ValueError(f"migrated YAML is invalid: {path}")
            yield path, original, migrated


def sqlite_query_columns(connection):
    """Return query-bearing tables available in the application database."""
    tables = []
    for table in ("tagrules", "reports"):
        columns = {
            row[1]
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if "query" in columns:
            tables.append(table)
    return tables


def load_sqlite_migrations(connection):
    """Read all custom rule/report query changes without modifying SQLite."""
    changes = []
    for table in sqlite_query_columns(connection):
        rows = connection.execute(
            f"SELECT rowid, query FROM {table} WHERE query IS NOT NULL"
        )
        for rowid, query in rows:
            migrated = rewrite_certificate_query(query)
            if migrated != query:
                changes.append((table, rowid, query, migrated))
    return changes


def migration_applied(connection):
    """Return whether the durable migration marker exists."""
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if MIGRATION_TABLE not in tables:
        return False
    return connection.execute(
        f"SELECT 1 FROM {MIGRATION_TABLE} WHERE name = ?",
        (MIGRATION_NAME,),
    ).fetchone() is not None


def apply_sqlite_migrations(connection, changes):
    """Apply query changes and marker in one SQLite transaction."""
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} ("
        "name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    for table, rowid, _old_query, new_query in changes:
        connection.execute(
            f"UPDATE {table} SET query = ? WHERE rowid = ?",
            (new_query, rowid),
        )
    connection.execute(
        f"INSERT INTO {MIGRATION_TABLE}(name, applied_at) VALUES (?, ?)",
        (MIGRATION_NAME, datetime.now(timezone.utc).isoformat()),
    )


def parse_args(argv=None):
    """Parse migration command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Migrate certificate queries from CN fields to x509_*_cn."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--yaml-dir", type=Path, default=DEFAULT_YAML_DIR)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    return parser.parse_args(argv)


def main(argv=None):
    """Preview or apply the YAML and SQLite query migration."""
    args = parse_args(argv)
    version = current_version()
    yaml_changes = list(iter_yaml_migrations(args.yaml_dir, version))

    if not args.db.exists():
        raise SystemExit(f"SQLite database not found: {args.db}")
    connection = sqlite3.connect(args.db)
    try:
        if migration_applied(connection):
            print(f"Migration marker already present: {MIGRATION_NAME}")
            return 0
        sqlite_changes = load_sqlite_migrations(connection)

        print(f"YAML files to migrate: {len(yaml_changes)}")
        for path, _original, _migrated in yaml_changes:
            print(f"  YAML {path}")
        print(f"SQLite queries to migrate: {len(sqlite_changes)}")
        for table, rowid, _old_query, _new_query in sqlite_changes:
            print(f"  SQLite {table} rowid={rowid}")

        if args.dry_run:
            return 0

        try:
            with connection:
                apply_sqlite_migrations(connection, sqlite_changes)
                for path, _original, migrated in yaml_changes:
                    temporary = path.with_suffix(path.suffix + ".tmp")
                    temporary.write_text(migrated, encoding="utf-8")
                    temporary.replace(path)
        except Exception:
            connection.rollback()
            raise
        print("Migration applied")
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
