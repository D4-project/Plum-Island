"""
Add scan profile cycle tracking tables and columns.
"""

# pylint: disable=invalid-name

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def column_exists(db_cursor, table_name, column_name):
    """
    Return True when a table already has the given column.
    """
    db_cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in db_cursor.fetchall())


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("PRAGMA foreign_keys=ON")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS scanprofile_cycles (
        id INTEGER NOT NULL PRIMARY KEY,
        scanprofile_id INTEGER NOT NULL,
        started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at DATETIME,
        status VARCHAR(32) NOT NULL DEFAULT 'running',
        target_count INTEGER NOT NULL DEFAULT 0,
        completed_target_count INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(scanprofile_id) REFERENCES scanprofiles(id)
    )
    """)

if not column_exists(cursor, "jobs", "scanprofile_cycle_id"):
    cursor.execute(
        "ALTER TABLE jobs ADD COLUMN scanprofile_cycle_id INTEGER REFERENCES scanprofile_cycles(id)"
    )

if not column_exists(cursor, "jobs", "scanprofile_name"):
    cursor.execute("ALTER TABLE jobs ADD COLUMN scanprofile_name VARCHAR(256)")

if not column_exists(cursor, "scanprofiles", "current_cycle_id"):
    cursor.execute("ALTER TABLE scanprofiles ADD COLUMN current_cycle_id INTEGER")

if not column_exists(cursor, "scanprofiles", "last_cycle_finished_at"):
    cursor.execute(
        "ALTER TABLE scanprofiles ADD COLUMN last_cycle_finished_at DATETIME"
    )

cursor.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS uq_scanprofile_cycles_one_running
        ON scanprofile_cycles(scanprofile_id)
        WHERE status = 'running'
    """)

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_scanprofile_cycles_profile_status
        ON scanprofile_cycles(scanprofile_id, status)
    """)

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_scanprofile_cycles_profile_started
        ON scanprofile_cycles(scanprofile_id, started_at DESC)
    """)

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_scanprofile_cycles_profile_finished
        ON scanprofile_cycles(scanprofile_id, finished_at DESC)
    """)

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_jobs_scanprofile_cycle
        ON jobs(scanprofile_cycle_id)
    """)

# Backfill one running cycle for scan profiles that already have unfinished
# jobs during upgrade. The scheduler will refresh counters on its next tick.
cursor.execute("""
    INSERT OR IGNORE INTO scanprofile_cycles (
        scanprofile_id,
        started_at,
        status,
        target_count,
        completed_target_count
    )
    SELECT j.scanprofile_id,
           COALESCE(MIN(j.job_creation), CURRENT_TIMESTAMP),
           'running',
           0,
           0
      FROM jobs AS j
     WHERE j.finished = 0
       AND j.scanprofile_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
              FROM scanprofile_cycles AS sc
             WHERE sc.scanprofile_id = j.scanprofile_id
               AND sc.status = 'running'
       )
     GROUP BY j.scanprofile_id
    """)

cursor.execute("""
    UPDATE jobs
       SET scanprofile_cycle_id = (
            SELECT sc.id
              FROM scanprofile_cycles AS sc
             WHERE sc.scanprofile_id = jobs.scanprofile_id
               AND sc.status = 'running'
             ORDER BY sc.started_at DESC, sc.id DESC
             LIMIT 1
       )
     WHERE finished = 0
       AND scanprofile_id IS NOT NULL
       AND scanprofile_cycle_id IS NULL
    """)

cursor.execute("""
    UPDATE jobs
       SET scanprofile_id = (
            SELECT sc.scanprofile_id
              FROM scanprofile_cycles AS sc
             WHERE sc.id = jobs.scanprofile_cycle_id
             LIMIT 1
       )
     WHERE scanprofile_id IS NULL
       AND scanprofile_cycle_id IS NOT NULL
    """)

cursor.execute("""
    UPDATE jobs
       SET scanprofile_name = (
            SELECT sp.name
              FROM scanprofiles AS sp
             WHERE sp.id = jobs.scanprofile_id
             LIMIT 1
       )
     WHERE scanprofile_name IS NULL
       AND scanprofile_id IS NOT NULL
    """)

cursor.execute("""
    UPDATE scanprofiles
       SET current_cycle_id = (
            SELECT sc.id
              FROM scanprofile_cycles AS sc
             WHERE sc.scanprofile_id = scanprofiles.id
               AND sc.status = 'running'
             ORDER BY sc.started_at DESC, sc.id DESC
             LIMIT 1
       )
     WHERE EXISTS (
            SELECT 1
              FROM scanprofile_cycles AS sc
             WHERE sc.scanprofile_id = scanprofiles.id
               AND sc.status = 'running'
       )
    """)

conn.commit()
conn.close()

print("Scan profile cycle tracking migration complete")
