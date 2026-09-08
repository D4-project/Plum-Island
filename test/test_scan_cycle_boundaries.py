"""Regression tests for bounded scan-profile cycles."""

# pylint: disable=protected-access,import-error

import importlib.util
import os
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.models import ScanProfileCycles  # pylint: disable=wrong-import-position
from app.utils import scan_cycles  # pylint: disable=wrong-import-position


class ScanCycleBoundaryTest(unittest.TestCase):
    """Validate cycle high-water marks and blocker presentation."""

    def test_new_cycle_keeps_supplied_target_boundary(self):
        """New cycle persists exact scheduler-captured boundary."""
        session = mock.Mock()
        with mock.patch.object(
            scan_cycles,
            "get_running_scanprofile_cycle",
            return_value=None,
        ), mock.patch.object(
            scan_cycles,
            "reconcile_scanprofile_cycle",
            side_effect=lambda _profile_id, cycle, now: cycle,
        ), mock.patch.object(
            scan_cycles.db, "session", session
        ):
            cycle = scan_cycles.get_or_create_running_cycle(
                7,
                max_target_id=123,
            )

        self.assertEqual(cycle.scanprofile_id, 7)
        self.assertEqual(cycle.max_target_id, 123)
        session.add.assert_called_once_with(cycle)
        session.flush.assert_called_once_with()

    def test_existing_cycle_boundary_never_expands(self):
        """Later target inserts cannot widen a running cycle."""
        cycle = ScanProfileCycles(
            scanprofile_id=7,
            status="running",
            max_target_id=123,
        )
        with mock.patch.object(
            scan_cycles,
            "get_running_scanprofile_cycle",
            return_value=cycle,
        ), mock.patch.object(
            scan_cycles,
            "reconcile_scanprofile_cycle",
            side_effect=lambda _profile_id, cycle, now: cycle,
        ):
            result = scan_cycles.get_or_create_running_cycle(
                7,
                max_target_id=999,
            )

        self.assertIs(result, cycle)
        self.assertEqual(cycle.max_target_id, 123)

    def test_new_cycle_can_be_committed_before_expensive_reconciliation(self):
        """Queue generation may release SQLite's writer before job staging."""
        session = mock.Mock()
        with mock.patch.object(
            scan_cycles,
            "get_running_scanprofile_cycle",
            return_value=None,
        ), mock.patch.object(
            scan_cycles,
            "reconcile_scanprofile_cycle",
        ) as reconcile, mock.patch.object(
            scan_cycles.db, "session", session
        ):
            cycle = scan_cycles.get_or_create_running_cycle(
                7,
                max_target_id=123,
                reconcile=False,
            )

        self.assertEqual(cycle.max_target_id, 123)
        session.flush.assert_called_once_with()
        reconcile.assert_not_called()

    def test_progress_title_exposes_completion_blockers(self):
        """Running-at-100-percent display explains remaining blockers."""
        title = ScanProfileCycles._progress_title(
            100,
            100,
            9,
            10,
            job_counts=(2, 1),
        )

        self.assertIn("100/100 IP scan", title)
        self.assertIn("1 incomplete target", title)
        self.assertIn("2 queued job", title)
        self.assertIn("1 active job", title)


class ScanCycleBoundaryMigrationTest(unittest.TestCase):
    """Validate migration of cycles with jobs already in progress."""

    @classmethod
    def setUpClass(cls):
        migration_path = (
            Path(__file__).resolve().parents[1]
            / "webapp"
            / "sql_upd"
            / "20_migrate_from_1a77f9638812f6d238b5a7f26aace1f45ae06e2e.py"
        )
        spec = importlib.util.spec_from_file_location(
            "scan_cycle_boundary_migration",
            migration_path,
        )
        cls.migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.migration)

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.cursor = self.connection.cursor()
        self.cursor.executescript("""
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY
            );
            CREATE TABLE scanprofile_cycles (
                id INTEGER PRIMARY KEY,
                status VARCHAR(32) NOT NULL
            );
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY,
                scanprofile_cycle_id INTEGER,
                active BOOLEAN NOT NULL,
                finished BOOLEAN NOT NULL
            );
            INSERT INTO targets (id) VALUES (10), (20), (30);
            INSERT INTO scanprofile_cycles (id, status)
                VALUES (1, 'running'), (2, 'finished');
            INSERT INTO jobs (id, scanprofile_cycle_id, active, finished)
                VALUES (1, 1, 0, 0), (2, 1, 1, 0), (3, 2, 0, 1);
            """)

    def tearDown(self):
        self.connection.close()

    def test_running_cycle_is_bounded_without_changing_jobs(self):
        """Migration preserves queued and active job rows."""
        jobs_before = self.cursor.execute("SELECT * FROM jobs ORDER BY id").fetchall()

        self.migration.migrate(self.cursor)

        cycles = self.cursor.execute(
            "SELECT id, status, max_target_id FROM scanprofile_cycles ORDER BY id"
        ).fetchall()
        jobs_after = self.cursor.execute("SELECT * FROM jobs ORDER BY id").fetchall()
        self.assertEqual(cycles, [(1, "running", 30), (2, "finished", None)])
        self.assertEqual(jobs_after, jobs_before)

    def test_rerun_does_not_expand_existing_cycle(self):
        """Idempotent rerun does not move existing high-water mark."""
        self.migration.migrate(self.cursor)
        self.cursor.execute("INSERT INTO targets (id) VALUES (40)")

        self.migration.migrate(self.cursor)

        max_target_id = self.cursor.execute(
            "SELECT max_target_id FROM scanprofile_cycles WHERE id = 1"
        ).fetchone()[0]
        self.assertEqual(max_target_id, 30)


if __name__ == "__main__":
    unittest.main()
