import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent
DB_PATH = BASE_DIR / "app.db"
TAGS_DIR = PROJECT_ROOT / "tags"
TAG_SPLIT_RE = re.compile(r"[\n,]+")


def utcnow_sql():
    """
    Return a SQLite-friendly UTC timestamp string.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def normalize_tags(tags):
    """
    Normalize tag values to unique lowercase strings.
    """
    normalized = []
    seen = set()
    for tag in tags or []:
        value = str(tag).strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def parse_tags_text(tags_value):
    """
    Parse editable tag text or JSON/YAML lists into normalized tags.
    """
    if tags_value is None:
        return []
    if isinstance(tags_value, list):
        return normalize_tags(tags_value)

    chunks = []
    for part in TAG_SPLIT_RE.split(str(tags_value)):
        candidate = str(part).strip()
        if candidate:
            chunks.append(candidate)
    return normalize_tags(chunks)


def format_tags_text(tags):
    """
    Serialize tags to the final DB format.
    """
    return "\n".join(parse_tags_text(tags))


def parse_rule_yaml(yaml_body):
    """
    Normalize one YAML rule body.
    """
    payload = yaml.safe_load(yaml_body or "") or {}
    if not isinstance(payload, dict):
        raise ValueError("Tag rule YAML must be a mapping")

    description = str(payload.get("description") or "").strip()
    query = str(payload.get("query") or "").strip()
    raw_tags = payload.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    if not isinstance(raw_tags, list):
        raise ValueError("Tag rule 'tags' must be a list")

    tags = parse_tags_text(raw_tags)
    if not description or not query or not tags:
        raise ValueError("Tag rule requires description, query and tags")

    return {
        "description": description,
        "query": query,
        "tags_text": format_tags_text(tags),
    }


def normalize_rule_fields(description, query, tags_value):
    """
    Normalize one DB-backed rule record.
    """
    description = str(description or "").strip()
    query = str(query or "").strip()
    tags_text = format_tags_text(tags_value)
    if not description or not query or not tags_text:
        raise ValueError("Tag rule requires description, query and tags")
    return {
        "description": description,
        "query": query,
        "tags_text": tags_text,
    }


def table_exists(cursor, table_name):
    """
    Return True when a SQLite table exists.
    """
    row = cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return bool(row)


def table_columns(cursor, table_name):
    """
    Return the ordered column names of a SQLite table.
    """
    rows = cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [row[1] for row in rows]


def create_final_table(cursor, table_name):
    """
    Create the final tagrules table layout.
    """
    cursor.execute(
        f"""
        CREATE TABLE {table_name} (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(256) NOT NULL UNIQUE,
            active BOOLEAN NOT NULL DEFAULT 1,
            description VARCHAR(512) NOT NULL,
            query TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


def migrate_existing_table(cursor):
    """
    Convert any pre-existing tagrules table to the final schema.
    """
    if not table_exists(cursor, "tagrules"):
        create_final_table(cursor, "tagrules")
        return 0

    columns = table_columns(cursor, "tagrules")
    if columns == [
        "id",
        "name",
        "active",
        "description",
        "query",
        "tags",
        "created_at",
        "updated_at",
    ]:
        rows = cursor.execute(
            "SELECT id, name, active, description, query, tags, created_at, updated_at FROM tagrules"
        ).fetchall()
        cursor.execute("DROP TABLE tagrules")
        create_final_table(cursor, "tagrules")
        migrated = 0
        for row in rows:
            normalized = normalize_rule_fields(row[3], row[4], row[5])
            cursor.execute(
                """
                INSERT INTO tagrules (
                    id, name, active, description, query, tags, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row[0],
                    row[1],
                    row[2],
                    normalized["description"],
                    normalized["query"],
                    normalized["tags_text"],
                    row[6],
                    row[7],
                ),
            )
            migrated += 1
        return migrated

    create_final_table(cursor, "tagrules_new")

    select_columns = []
    for column_name in [
        "id",
        "name",
        "active",
        "description",
        "query",
        "tags",
        "tags_json",
        "yaml_body",
        "created_at",
        "updated_at",
    ]:
        if column_name in columns:
            select_columns.append(column_name)

    if not select_columns:
        cursor.execute("DROP TABLE tagrules")
        cursor.execute("ALTER TABLE tagrules_new RENAME TO tagrules")
        return 0

    query = f"SELECT {', '.join(select_columns)} FROM tagrules"
    rows = cursor.execute(query).fetchall()
    migrated = 0

    for row in rows:
        record = dict(zip(select_columns, row))
        created_at = record.get("created_at") or utcnow_sql()
        updated_at = record.get("updated_at") or created_at
        try:
            if record.get("yaml_body"):
                normalized = parse_rule_yaml(record["yaml_body"])
            elif "tags_json" in record and record.get("tags_json"):
                normalized = normalize_rule_fields(
                    record.get("description"),
                    record.get("query"),
                    json.loads(record.get("tags_json") or "[]"),
                )
            else:
                normalized = normalize_rule_fields(
                    record.get("description"),
                    record.get("query"),
                    record.get("tags", ""),
                )
        except Exception as error:
            print(
                f"Skipping existing rule {record.get('name', '<unknown>')}: {error}",
                flush=True,
            )
            continue

        cursor.execute(
            """
            INSERT INTO tagrules_new (
                id, name, active, description, query, tags, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get("id"),
                record.get("name"),
                record.get("active", 1),
                normalized["description"],
                normalized["query"],
                normalized["tags_text"],
                created_at,
                updated_at,
            ),
        )
        migrated += 1

    cursor.execute("DROP TABLE tagrules")
    cursor.execute("ALTER TABLE tagrules_new RENAME TO tagrules")
    return migrated


def import_tag_folder(cursor):
    """
    Seed DB-backed tag rules from tags/*.yaml when present.
    """
    imported = 0
    skipped = 0
    if not TAGS_DIR.is_dir():
        return imported, skipped

    for yaml_file in sorted(TAGS_DIR.glob("*.yaml")):
        try:
            normalized = parse_rule_yaml(yaml_file.read_text(encoding="utf-8"))
        except Exception as error:
            print(f"Skipping {yaml_file.name}: {error}", flush=True)
            skipped += 1
            continue

        cursor.execute(
            """
            INSERT INTO tagrules (
                name,
                active,
                description,
                query,
                tags,
                created_at,
                updated_at
            )
            VALUES (?, 1, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                query = excluded.query,
                tags = excluded.tags,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                yaml_file.stem,
                normalized["description"],
                normalized["query"],
                normalized["tags_text"],
            ),
        )
        imported += 1
    return imported, skipped


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

migrated_rows = migrate_existing_table(cursor)
imported_rules, skipped_rules = import_tag_folder(cursor)

conn.commit()
conn.close()

print(
    "Tag rules migration complete: "
    f"migrated_rows={migrated_rows} "
    f"imported_rules={imported_rules} "
    f"skipped_rules={skipped_rules}",
    flush=True,
)
