"""Regression tests for upgrades of existing, unversioned Plum installations."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tools import update_sql


class UpdateSqlTest(unittest.TestCase):
    """Run the real numbered migrations on a disposable pre-24 schema."""

    def setUp(self):
        # enterContext releases the directory and connection after each test.
        # pylint: disable-next=consider-using-with
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = folder / "app.db"
        self.scripts = folder / "sql_upd"
        self.scripts.mkdir()
        for number in (24, 25):
            shutil.copy(
                next(update_sql.MIGRATIONS.glob(f"{number}_*.py")), self.scripts
            )
        self.conn = self.enterContext(closing(sqlite3.connect(self.path)))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
            CREATE TABLE jobs (scan_unit_count, nmap_additional_params, meili_task_uid,
                               meili_documents_submitted, meili_documents_total);
            CREATE TABLE scanprofiles (id INTEGER PRIMARY KEY, name TEXT,
                                       current_cycle_id, nmap_additional_params);
            CREATE TABLE scanprofile_cycles (max_target_id, completed_scan_unit_count);
            CREATE TABLE collected_headers (header_name, collect_value);
            CREATE TABLE tagrules (uuid);
            CREATE TABLE target_scan_states (target_id, scanprofile_id);
            CREATE TABLE autonomous_systems (asn, updated_at);
            CREATE TABLE targets (id INTEGER PRIMARY KEY, value TEXT, created_at,
                                  network_asn, network_updated_at, network_refresh_pending,
                                  network_retry_at, network_claim, network_claim_until);
            INSERT INTO targets (value) VALUES ('192.0.2.1'), ('example.org');
            INSERT INTO scanprofiles (name) VALUES ('daily');
        """)

    def update(self):
        """Run the two migrations represented by this historical fixture."""
        update_sql.update_database(self.path, self.scripts)

    def test_concurrent_upgrade_backup_and_repeat(self):
        """Both runs succeed and one backup captures the committed WAL."""
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(self.update), pool.submit(self.update)
            first.result()
            second.result()
        self.update()
        backups = list(self.path.parent.glob("app.db.before-sql-update-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with closing(sqlite3.connect(backups[0])) as backup:
            self.assertEqual(
                backup.execute("SELECT name FROM scanprofiles").fetchall(), [("daily",)]
            )
            self.assertNotIn(
                "is_ip_cidr",
                [row[1] for row in backup.execute("PRAGMA table_info(targets)")],
            )
        self.assertEqual(
            self.conn.execute("SELECT is_ip_cidr FROM targets ORDER BY id").fetchall(),
            [(1,), (0,)],
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO scanprofiles(name) VALUES ('daily')")

    def test_failure_rolls_back_batch_and_can_retry(self):
        """A duplicate at step 25 rolls back step 24 and the version history."""
        with self.conn:
            self.conn.execute("INSERT INTO scanprofiles(name) VALUES ('daily')")
        with self.assertRaisesRegex(ValueError, "1,2"):
            self.update()
        self.assertNotIn(
            "is_ip_cidr",
            [row[1] for row in self.conn.execute("PRAGMA table_info(targets)")],
        )
        self.assertIsNone(
            self.conn.execute(
                "SELECT name FROM sqlite_master WHERE name='plum_schema_migrations'"
            ).fetchone()
        )
        with self.conn:
            self.conn.execute("UPDATE scanprofiles SET name='weekly' WHERE id=2")
        self.update()
        self.assertEqual(
            self.conn.execute(
                "SELECT version FROM plum_schema_migrations ORDER BY version"
            ).fetchall(),
            [(23,), (24,), (25,)],
        )

    def test_manual_migrations_and_new_file(self):
        """Adopt an existing unique index, then discover the next numbered file."""
        with self.conn:
            self.conn.execute(
                "ALTER TABLE targets ADD COLUMN is_ip_cidr BOOLEAN NOT NULL DEFAULT 0"
            )
            self.conn.execute("UPDATE targets SET is_ip_cidr=1 WHERE id=1")
            self.conn.execute(
                "CREATE UNIQUE INDEX ix_scanprofiles_name ON scanprofiles(name)"
            )
        self.update()
        next_script = self.scripts / ("26_migrate_from_" + "a" * 40 + ".py")
        next_script.write_text(
            "def migrate(conn):\n    conn.execute('CREATE TABLE unfinished (id)')\n    conn.commit()\n",
            encoding="utf-8",
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.update()
        self.assertIsNone(
            self.conn.execute(
                "SELECT name FROM sqlite_master WHERE name='unfinished'"
            ).fetchone()
        )
        next_script.write_text(
            "def migrate(conn):\n    conn.execute('CREATE TABLE test_added (id INTEGER)')\n",
            encoding="utf-8",
        )
        self.update()
        self.update()
        self.assertEqual(
            self.conn.execute(
                "SELECT MAX(version) FROM plum_schema_migrations"
            ).fetchone(),
            (26,),
        )
        next_script.unlink()
        with self.assertRaisesRegex(ValueError, "newer"):
            self.update()

    def test_refuses_wrong_or_missing_database(self):
        """Do not initialize unknown or missing databases during an update."""
        missing = self.path.with_name("missing.db")
        with self.assertRaisesRegex(ValueError, "does not exist"):
            update_sql.update_database(missing)
        self.assertFalse(missing.exists())
        with self.conn:
            self.conn.execute("DROP TABLE jobs")
        with self.assertRaisesRegex(ValueError, "documentation/migration.md"):
            update_sql.update_database(self.path)
        self.assertFalse(list(self.path.parent.glob("*.before-sql-update-*")))

    def test_shell_updates_configured_db_before_roles(self):
        """Exercise the update entry point from outside the checkout, without network."""
        root = self.path.parent / "deployment"
        root.mkdir()
        shutil.copy(update_sql.WEBAPP.parent / "updisland.sh", root)
        python = root / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text(
            f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n', encoding="utf-8"
        )
        python.chmod(0o700)
        git = python.parent / "git"
        git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        git.chmod(0o700)
        webapp = root / "webapp"
        webapp.mkdir()
        shutil.copytree(self.scripts, webapp / "sql_upd")
        (webapp / "app").symlink_to(update_sql.WEBAPP / "app", target_is_directory=True)
        (webapp / "config.py").write_text(
            f"SQLALCHEMY_DATABASE_URI = 'sqlite:///{self.path}'\n", encoding="utf-8"
        )
        tools = root / "tools"
        tools.mkdir()
        shutil.copy(update_sql.__file__, tools)
        (tools / "initial_setup.py").write_text(
            "import sys\nfrom pathlib import Path\n"
            "assert sys.argv[1:] == ['--roles-only']\nPath('roles-called').touch()\n",
            encoding="utf-8",
        )
        command = [str(root / "updisland.sh")]
        env = {**os.environ, "PATH": f"{git.parent}:{os.environ['PATH']}"}
        with self.conn:
            self.conn.execute("INSERT INTO scanprofiles(name) VALUES ('daily')")
        failed = subprocess.run(
            command,
            cwd=self.path.parent,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("duplicate scan profiles", failed.stderr)
        self.assertFalse((root / "roles-called").exists())
        with self.conn:
            self.conn.execute("UPDATE scanprofiles SET name='weekly' WHERE id=2")
        subprocess.run(
            command, cwd=self.path.parent, env=env, capture_output=True, check=True
        )
        self.assertTrue((root / "roles-called").exists())
