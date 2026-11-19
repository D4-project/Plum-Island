"""Migration 22: add mandatory unique UUID identities to SQLite tag rules."""

# pylint: disable=invalid-name

import sqlite3
from pathlib import Path
from uuid import UUID, uuid4

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"
TAGS_DIR = BASE_DIR / "tags" / "tags"
TAGRULE_COLUMNS = (
    "id",
    "uuid",
    "name",
    "active",
    "description",
    "query",
    "tags",
    "created_at",
    "updated_at",
)


def canonical_uuid(value):
    """Return canonical UUID text or ``None`` when value is missing/invalid."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value else None


def table_exists(cursor, table_name):
    """Return whether one SQLite table exists."""
    return bool(
        cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    )


def tagrules_has_target_schema(cursor):
    """Return whether UUID is unique and ``name`` deliberately is not."""
    columns = {
        row[1]: row for row in cursor.execute("PRAGMA table_info(tagrules)").fetchall()
    }
    uuid_column = columns.get("uuid")
    if uuid_column is None or not uuid_column[3]:
        return False
    has_uuid_index = False
    for index in cursor.execute("PRAGMA index_list(tagrules)").fetchall():
        if not index[2]:
            continue
        names = [
            row[2]
            for row in cursor.execute(f"PRAGMA index_info({index[1]})").fetchall()
        ]
        if names == ["uuid"]:
            has_uuid_index = True
        if names == ["name"]:
            return False
    return has_uuid_index


def load_yaml_uuids(tags_dir):
    """Map rule filename stems to validated unique UUIDs from YAML metadata."""
    identifiers = {}
    seen = set()
    for path in sorted(Path(tags_dir).glob("*.yaml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise ValueError(f"Cannot load {path.name}: {error}") from error
        value = payload.get("uuid") if isinstance(payload, dict) else None
        rule_uuid = canonical_uuid(value)
        if rule_uuid is None:
            raise ValueError(f"{path.name}: missing or invalid UUID")
        if rule_uuid in seen:
            raise ValueError(f"{path.name}: duplicate UUID {rule_uuid}")
        identifiers[path.stem] = rule_uuid
        seen.add(rule_uuid)
    return identifiers


def next_uuid(used):
    """Generate a UUID not already allocated during this migration."""
    while True:
        value = str(uuid4())
        if value not in used:
            return value


def prepare_rows(cursor, yaml_uuids):
    """Return existing tagrules rows with one safe, unique UUID per row."""
    columns = [
        row[1] for row in cursor.execute("PRAGMA table_info(tagrules)").fetchall()
    ]
    select_columns = [column for column in TAGRULE_COLUMNS if column in columns]
    rows = cursor.execute(
        f"SELECT {', '.join(select_columns)} FROM tagrules"
    ).fetchall()
    prepared = []
    generated = 0
    used = set()
    reserved_yaml_uuids = set(yaml_uuids.values())
    for row in rows:
        record = dict(zip(select_columns, row))
        yaml_uuid = yaml_uuids.get(record["name"])
        existing_uuid = canonical_uuid(record.get("uuid"))
        rule_uuid = yaml_uuid or existing_uuid
        if rule_uuid is None:
            rule_uuid = next_uuid(used | reserved_yaml_uuids)
            generated += 1
        if rule_uuid in used:
            raise ValueError(f"Duplicate UUID while migrating rule {record['name']}")
        used.add(rule_uuid)
        prepared.append(
            (
                record["id"],
                rule_uuid,
                record["name"],
                record.get("active", 1),
                record["description"],
                record["query"],
                record.get("tags", ""),
                record.get("created_at"),
                record.get("updated_at"),
            )
        )
    return prepared, generated


def create_strict_tagrules_table(cursor, table_name):
    """Create the UUID-enforced tagrules SQLite schema at a trusted table name."""
    cursor.execute(f"""
        CREATE TABLE {table_name} (
            id INTEGER NOT NULL PRIMARY KEY,
            uuid VARCHAR(36) NOT NULL UNIQUE,
            name VARCHAR(256) NOT NULL,
            active BOOLEAN NOT NULL DEFAULT 1,
            description VARCHAR(512) NOT NULL,
            query TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)


def migrate(connection, tags_dir=TAGS_DIR):
    """Backfill YAML UUIDs and rebuild tagrules only when constraints are absent."""
    cursor = connection.cursor()
    if not table_exists(cursor, "tagrules"):
        return {"migrated": 0, "generated": 0, "rebuilt": False}

    yaml_uuids = load_yaml_uuids(tags_dir)
    rows, generated = prepare_rows(cursor, yaml_uuids)
    if tagrules_has_target_schema(cursor):
        cursor.executemany(
            "UPDATE tagrules SET uuid = ? WHERE id = ?",
            [(row[1], row[0]) for row in rows],
        )
        return {"migrated": len(rows), "generated": generated, "rebuilt": False}

    cursor.execute("DROP TABLE IF EXISTS tagrules_uuid_migration")
    create_strict_tagrules_table(cursor, "tagrules_uuid_migration")
    cursor.executemany(
        """
        INSERT INTO tagrules_uuid_migration (
            id, uuid, name, active, description, query, tags, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    cursor.execute("DROP TABLE tagrules")
    cursor.execute("ALTER TABLE tagrules_uuid_migration RENAME TO tagrules")
    return {"migrated": len(rows), "generated": generated, "rebuilt": True}


def main():
    """Apply the UUID migration to the configured Plum Island SQLite database."""
    connection = sqlite3.connect(DB_PATH)
    try:
        summary = migrate(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    print(
        "Tag rule UUID migration complete: "
        f"migrated={summary['migrated']} generated={summary['generated']} "
        f"rebuilt={summary['rebuilt']}"
    )


if __name__ == "__main__":
    main()
