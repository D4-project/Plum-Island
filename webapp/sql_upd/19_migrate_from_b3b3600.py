"""Add profile-level Nmap parameters to profiles and queued jobs."""

# pylint: disable=invalid-name,redefined-outer-name

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def column_exists(cursor, table_name, column_name):
    """Return whether a SQLite table already contains a column."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in cursor.fetchall())


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

if not column_exists(cursor, "scanprofiles", "nmap_additional_params"):
    cursor.execute("ALTER TABLE scanprofiles ADD COLUMN nmap_additional_params TEXT")
if not column_exists(cursor, "jobs", "nmap_additional_params"):
    cursor.execute("ALTER TABLE jobs ADD COLUMN nmap_additional_params TEXT")

conn.commit()
conn.close()

print("Nmap additional params migration complete")
