"""Regression tests for the tag-rule UUID SQLite migration."""

import importlib.util
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase

MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "webapp"
    / "sql_upd"
    / "22_migrate_from_e1e711f41e9239b02bdba58dc4a9a5588d89619e.py"
)
SPEC = importlib.util.spec_from_file_location("tagrule_uuid_migration", MIGRATION_PATH)
MIGRATION = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MIGRATION)


class TagRuleUuidMigrationTests(TestCase):
    """Verify UUID identity and non-unique display names after migration."""

    def test_migration_backfills_uuid_and_allows_duplicate_names(self):
        """Use YAML UUIDs for legacy file-named rules and rebuild once."""
        connection = sqlite3.connect(":memory:")
        connection.execute("""
            CREATE TABLE tagrules (
                id INTEGER PRIMARY KEY,
                name VARCHAR(256) NOT NULL UNIQUE,
                active BOOLEAN NOT NULL DEFAULT 1,
                description VARCHAR(512) NOT NULL,
                query TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """)
        connection.execute(
            "INSERT INTO tagrules (id, name, description, query, tags) "
            "VALUES (1, 'legacy-filename', 'Legacy', 'banner:legacy', 'type:service')"
        )

        with tempfile.TemporaryDirectory() as directory:
            tags_dir = Path(directory)
            source_uuid = "9fc4762c-406d-4765-9c72-1353ae8579ae"
            (tags_dir / "legacy-filename.yaml").write_text(
                f"uuid: {source_uuid}\n", encoding="utf-8"
            )
            summary = MIGRATION.migrate(connection, tags_dir)
            connection.commit()

        self.assertTrue(summary["rebuilt"])
        self.assertEqual(
            connection.execute("SELECT uuid FROM tagrules WHERE id = 1").fetchone()[0],
            source_uuid,
        )
        connection.execute(
            "INSERT INTO tagrules (uuid, name, description, query, tags) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "6b9d1bf0-725f-4079-b58e-61482173e121",
                "legacy-filename",
                "Another",
                "banner:another",
                "type:service",
            ),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO tagrules (uuid, name, description, query, tags) "
                "VALUES (?, ?, ?, ?, ?)",
                (source_uuid, "other", "Other", "banner:other", "type:service"),
            )
        connection.rollback()
        connection.close()
