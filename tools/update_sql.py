"""Apply pending Plum SQLite migrations before starting the application."""

import argparse
from contextlib import closing
from importlib import import_module
from pathlib import Path
import re
import runpy
import sqlite3
import sys
import tempfile

from sqlalchemy.engine import make_url

WEBAPP = Path(__file__).resolve().parents[1] / "webapp"
MIGRATIONS = WEBAPP / "sql_upd"
# Earlier releases have coordinated SQL, Meilisearch and Kvrocks upgrade steps.
BASELINE = 23
BASELINE_COLUMNS = {
    "scanprofiles": {"id", "name", "current_cycle_id", "nmap_additional_params"},
    "jobs": {
        "scan_unit_count",
        "meili_task_uid",
        "meili_documents_submitted",
        "meili_documents_total",
        "nmap_additional_params",
    },
    "scanprofile_cycles": {"max_target_id", "completed_scan_unit_count"},
    "collected_headers": {"header_name", "collect_value"},
    "tagrules": {"uuid"},
    "target_scan_states": {"target_id", "scanprofile_id"},
    "autonomous_systems": {"asn", "updated_at"},
    "targets": {
        "id",
        "value",
        "created_at",
        "network_asn",
        "network_updated_at",
        "network_refresh_pending",
        "network_retry_at",
        "network_claim",
        "network_claim_until",
    },
}


def configured_database():
    """Resolve the same database as Flask-SQLAlchemy without starting Flask."""
    sys.path.insert(0, str(WEBAPP))
    url = make_url(import_module("config").SQLALCHEMY_DATABASE_URI)
    if url.get_backend_name() != "sqlite":
        print(
            f"Configured backend is {url.get_backend_name()}. Skipping SQLite migrations. "
            "Manage equivalent schema changes using your database's deployment procedure."
        )
        return None
    if not url.database or url.database == ":memory:" or url.query.get("uri") == "true":
        raise ValueError("Expected a persistent SQLite file in SQLALCHEMY_DATABASE_URI")
    return WEBAPP / "app" / url.database


def migration_files(directory):
    """Find numbered migrations in sequence. Never import historical scripts."""
    scripts = {}
    for path in directory.glob("*.py"):
        match = re.fullmatch(r"(\d{2,})_migrate_from_[0-9a-f]{40}\.py", path.name)
        if not match:
            raise ValueError(f"Invalid migration filename: {path.name}")
        number = int(match[1])
        if number <= BASELINE:
            continue
        if number in scripts:
            raise ValueError(f"Duplicate migration number: {number}")
        scripts[number] = path
    if not scripts or sorted(scripts) != list(range(BASELINE + 1, max(scripts) + 1)):
        raise ValueError("Missing migration file in webapp/sql_upd")
    return scripts


def existing_version(connection, latest):
    """Read recorded history or recognize an installation predating the ledger."""
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='plum_schema_migrations'"
    ).fetchone():
        versions = [
            row[0]
            for row in connection.execute(
                "SELECT version FROM plum_schema_migrations ORDER BY version"
            )
        ]
        if (
            not versions
            or versions[-1] > latest
            or versions != list(range(BASELINE, versions[-1] + 1))
        ):
            raise ValueError(
                "Migration history is incomplete or newer than this checkout"
            )
        return versions[-1], True
    for table, required in BASELINE_COLUMNS.items():
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        missing = required - columns
        if missing:
            raise ValueError(
                f"Unrecognized pre-migration schema ({table} lacks {', '.join(sorted(missing))}). "
                "Check the configured database and the upgrade path in documentation/migration.md."
            )
    # Migration 24 added this NOT NULL column and backfilled it atomically.
    if any(
        row[1] == "is_ip_cidr" and row[3]
        for row in connection.execute("PRAGMA table_info(targets)")
    ):
        return 24, False
    return BASELINE, False


def backup_database(path):
    """Capture committed data, including the WAL, before changing the schema."""
    with tempfile.NamedTemporaryFile(
        prefix=path.name + ".before-sql-update-", dir=path.parent, delete=False
    ) as handle:
        backup = Path(handle.name)
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(backup)) as destination:
                source.backup(destination)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def update_database(path, directory=MIGRATIONS):
    """Serialize updaters and commit migrations and history together."""
    path = path.resolve()
    scripts = migration_files(directory)
    latest = max(scripts)
    if not path.is_file():
        raise ValueError(
            f"Configured database does not exist: {path}. For a new install run setup.sh."
        )
    with closing(
        sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=30)
    ) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        version, recorded = existing_version(conn, latest)
        if version == latest and recorded:
            print(f"SQLite {path} is up to date (migration {version}).")
            return
        print(f"SQLite backup: {backup_database(path)}", flush=True)
        if not recorded:
            conn.execute(
                "CREATE TABLE plum_schema_migrations (version INTEGER PRIMARY KEY)"
            )
            conn.executemany(
                "INSERT INTO plum_schema_migrations VALUES (?)",
                [(number,) for number in range(BASELINE, version + 1)],
            )
        for number in range(version + 1, latest + 1):
            print(f"Applying SQLite migration {number}...", flush=True)
            # This also blocks executescript()'s implicit commit.
            conn.set_authorizer(
                lambda action, *_: (
                    sqlite3.SQLITE_DENY
                    if action == sqlite3.SQLITE_TRANSACTION
                    else sqlite3.SQLITE_OK
                )
            )
            try:
                runpy.run_path(str(scripts[number]))["migrate"](conn)
            finally:
                conn.set_authorizer(None)
            conn.execute("INSERT INTO plum_schema_migrations VALUES (?)", (number,))
        conn.commit()
    print(f"SQLite {path} is up to date (migration {latest}).")


def main():
    """Run against the configured database or an explicit backup copy."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", type=Path, help="Use this SQLite database instead of config.py"
    )
    args = parser.parse_args()
    try:
        path = args.db or configured_database()
        if path is not None:
            update_database(path)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, f"SQLite update failed: {error}\n")


if __name__ == "__main__":
    main()
