import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in cursor.fetchall())


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

if not column_exists(cursor, "scanprofiles", "priority_retag_pending"):
    cursor.execute(
        "ALTER TABLE scanprofiles ADD COLUMN priority_retag_pending BOOLEAN NOT NULL DEFAULT 0"
    )

cursor.execute(
    """
    CREATE INDEX IF NOT EXISTS idx_jobs_waiting_priority_creation
        ON jobs(priority, job_creation)
        WHERE active = 0 AND finished = 0
    """
)

cursor.execute(
    """
    CREATE INDEX IF NOT EXISTS idx_target_scan_states_working_target_profile
        ON target_scan_states(working, target_id, scanprofile_id)
    """
)

conn.commit()
conn.close()

print("Job priority queue migration complete")
