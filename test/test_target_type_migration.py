"""Persisted target type: classification and atomic migration regressions."""

import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT / "webapp/sql_upd/24_migrate_from_610859bfc6d1d92ed54d48bceab1565753043742.py"
)
SPEC = importlib.util.spec_from_file_location("target_type_migration", SCRIPT)
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


class TargetTypeMigrationTest(unittest.TestCase):
    """Migration must preserve targets, abort invalid rows and tolerate reruns."""

    def setUp(self):
        self.folder = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(self.folder) / "test.db"
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE targets (id INTEGER PRIMARY KEY, value TEXT, description TEXT)"
            )
            connection.executemany(
                "INSERT INTO targets VALUES (?, ?, 'unchanged')",
                [
                    (1, "8.8.8.8"),
                    (2, "9.9.9.12/24"),
                    (3, "2606:4700:4700::1111"),
                    (4, "2001:4860::/32"),
                    (5, "example.org"),
                    (6, "device.example.local"),
                    (
                        7,
                        "10.0.0.1",
                    ),  # Classify legacy data, don't change admission policy.
                ],
            )

    def test_backfill_rerun_and_preservation(self):
        """Only derived metadata changes; reruns perform no writes."""
        with sqlite3.connect(self.path) as connection:
            original = connection.execute("SELECT * FROM targets").fetchall()
            connection.execute("BEGIN IMMEDIATE")
            summary = MIGRATION.migrate(connection)
            connection.commit()
            self.assertEqual((summary["ip_cidr"], summary["fqdn"]), (5, 2))
            self.assertEqual(
                connection.execute(
                    "SELECT id,value,description FROM targets"
                ).fetchall(),
                original,
            )
            self.assertEqual(
                [
                    r[0]
                    for r in connection.execute(
                        "SELECT is_ip_cidr FROM targets ORDER BY id"
                    )
                ],
                [1, 1, 1, 1, 0, 0, 1],
            )
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(MIGRATION.migrate(connection)["updated"], 0)
            connection.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE targets SET is_ip_cidr = NULL WHERE id = 1")

    def test_invalid_syntax_aborts_before_schema_change(self):
        """Bad IP syntax is not silently classified as a hostname."""
        with sqlite3.connect(self.path) as connection:
            connection.execute("INSERT INTO targets VALUES (8, '999.8.8.8', '')")
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(ValueError, "target IDs: \\[8\\]"):
                MIGRATION.migrate(connection)
            connection.rollback()
            self.assertNotIn(
                "is_ip_cidr",
                [r[1] for r in connection.execute("PRAGMA table_info(targets)")],
            )

    def test_cli_dry_run_apply_and_missing_database(self):
        """CLI applies without backup options and never creates a missing DB."""
        before = self.path.read_bytes()
        subprocess.run(
            [sys.executable, str(SCRIPT), "--db", str(self.path), "--dry-run"],
            check=True,
            capture_output=True,
        )
        self.assertEqual(self.path.read_bytes(), before)
        command = [
            sys.executable,
            str(SCRIPT),
            "--db",
            str(self.path),
        ]
        subprocess.run(command, check=True, capture_output=True)
        with sqlite3.connect(self.path) as connection:
            self.assertIn(
                "is_ip_cidr",
                [r[1] for r in connection.execute("PRAGMA table_info(targets)")],
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM targets").fetchone()[0], 7
            )
        self.assertEqual(
            subprocess.run(command, capture_output=True, check=False).returncode, 0
        )
        self.assertEqual(list(Path(self.folder).iterdir()), [self.path])
        missing = Path(self.folder) / "missing.db"
        self.assertNotEqual(
            subprocess.run(
                [sys.executable, str(SCRIPT), "--db", str(missing), "--dry-run"],
                capture_output=True,
                check=False,
            ).returncode,
            0,
        )
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
