#!/usr/bin/env python3
"""Tests for certificate query migration helpers."""

import sqlite3
import sys
from unittest import TestCase, main

ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "tools"))

from migrate_full_cert import (  # pylint: disable=wrong-import-position
    apply_sqlite_migrations,
    load_sqlite_migrations,
    migration_applied,
    rewrite_certificate_query,
)


class MigrateFullCertTest(TestCase):
    """Verify safe query rewriting and idempotent SQLite migration state."""

    def test_rewrites_fields_and_preserves_quoted_values(self):
        query = (
            'x509_issuer.lk:dahua OR x509_subject.bg:"CN=example" '
            'OR http_title.lk:"x509_issuer:literal"'
        )
        self.assertEqual(
            rewrite_certificate_query(query),
            'x509_issuer_cn.lk:dahua OR x509_subject_cn.bg:"CN=example" '
            'OR http_title.lk:"x509_issuer:literal"',
        )

    def test_sqlite_migration_updates_rules_and_marks_once(self):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE tagrules (query TEXT)")
        connection.execute("CREATE TABLE reports (query TEXT)")
        connection.execute(
            'INSERT INTO tagrules(query) VALUES ("x509_issuer.lk:mythic")'
        )
        connection.execute(
            'INSERT INTO reports(query) VALUES ("x509_subject:bg")'
        )

        changes = load_sqlite_migrations(connection)
        self.assertEqual(len(changes), 2)
        apply_sqlite_migrations(connection, changes)
        connection.commit()

        self.assertTrue(migration_applied(connection))
        self.assertEqual(
            connection.execute("SELECT query FROM tagrules").fetchone()[0],
            "x509_issuer_cn.lk:mythic",
        )
        self.assertEqual(load_sqlite_migrations(connection), [])
        connection.close()


if __name__ == "__main__":
    main()
