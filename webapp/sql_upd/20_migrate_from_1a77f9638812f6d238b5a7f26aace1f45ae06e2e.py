"""Add a target-ID high-water mark to scan profile cycles."""

# pylint: disable=invalid-name

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def column_exists(db_cursor, table_name, column_name):
    """Return whether a SQLite table already contains a column."""
    db_cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in db_cursor.fetchall())


def migrate(db_cursor):
    """
    Add and backfill cycle bounds without changing queued or active jobs.

    Existing running cycles receive the maximum target ID visible during the
    migration. Finished cycles keep NULL because their historical boundary
    cannot be reconstructed reliably.
    """
    if not column_exists(db_cursor, "scanprofile_cycles", "max_target_id"):
        db_cursor.execute(
            "ALTER TABLE scanprofile_cycles ADD COLUMN max_target_id INTEGER"
        )

    db_cursor.execute("""
        UPDATE scanprofile_cycles
           SET max_target_id = (SELECT COALESCE(MAX(id), 0) FROM targets)
         WHERE status = 'running'
           AND max_target_id IS NULL
        """)


def main():
    """Apply migration to application SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")

    migrate(cursor)

    conn.commit()
    conn.close()
    print("Scan profile cycle target boundary migration complete")


if __name__ == "__main__":
    main()
