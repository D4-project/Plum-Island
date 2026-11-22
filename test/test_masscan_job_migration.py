"""Job snapshot migration for Nmap and Masscan dispatch."""

import runpy
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path


class MasscanJobMigrationTest(unittest.TestCase):
    """Regression checks for masscan job migration test."""

    def test_pending_jobs_follow_profiles_and_active_jobs_stay_nmap(self):
        """Verify pending jobs follow profiles and active jobs stay nmap."""
        directory = Path(__file__).resolve().parents[1] / "webapp/sql_upd"
        migrate = runpy.run_path(str(next(directory.glob("29_*.py"))))["migrate"]
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.executescript("""
                CREATE TABLE scanprofiles (
                    id INTEGER PRIMARY KEY,
                    scan_tool TEXT NOT NULL DEFAULT 'nmap',
                    detect_protocol BOOLEAN NOT NULL DEFAULT 0
                );
                CREATE TABLE jobs (
                    id INTEGER PRIMARY KEY,
                    scanprofile_id INTEGER,
                    active BOOLEAN NOT NULL DEFAULT 0,
                    finished BOOLEAN NOT NULL DEFAULT 0
                );
                INSERT INTO scanprofiles VALUES (1, 'masscan', 1);
                INSERT INTO jobs VALUES (1, 1, 0, 0);
                INSERT INTO jobs VALUES (2, 1, 1, 0);
                INSERT INTO jobs VALUES (3, NULL, 0, 0);
            """)
            migrate(connection)
            migrate(connection)
            rows = connection.execute(
                "SELECT id, scan_tool, detect_protocol FROM jobs ORDER BY id"
            ).fetchall()
            self.assertEqual(
                rows,
                [(1, "masscan", 1), (2, "nmap", 0), (3, "nmap", 0)],
            )

    def test_attempt_migration_keeps_legacy_agents_compatible(self):
        """Verify attempt migration keeps legacy agents compatible."""
        directory = Path(__file__).resolve().parents[1] / "webapp/sql_upd"
        migrate = runpy.run_path(str(next(directory.glob("30_*.py"))))["migrate"]
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.executescript("""
                CREATE TABLE bots (id INTEGER PRIMARY KEY, uid TEXT);
                CREATE TABLE jobs (id INTEGER PRIMARY KEY, uid TEXT);
                INSERT INTO bots (uid) VALUES ('legacy');
                INSERT INTO jobs (uid) VALUES ('job');
            """)
            migrate(connection)
            migrate(connection)
            self.assertEqual(
                connection.execute("SELECT supports_job_attempts FROM bots").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute("SELECT attempt_uid FROM jobs").fetchone(),
                (None,),
            )


if __name__ == "__main__":
    unittest.main()
