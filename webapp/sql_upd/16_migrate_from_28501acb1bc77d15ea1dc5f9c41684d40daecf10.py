"""
Add scan-unit counters for scan profile cycle progress.
"""

# pylint: disable=duplicate-code,invalid-name

import ipaddress
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"
MAX_SCAN_UNIT_COUNT = 2**63 - 1


def column_exists(db_cursor, table_name, column_name):
    """
    Return True when a table already has the given column.
    """
    db_cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in db_cursor.fetchall())


def compute_scan_unit_count(value):
    """
    Count concrete scan units represented by one target value.
    """
    value = str(value or "").strip().rstrip(".")
    if not value:
        return 1

    try:
        ipaddress.ip_address(value)
        return 1
    except ValueError:
        pass

    try:
        return min(
            int(ipaddress.ip_network(value, strict=False).num_addresses),
            MAX_SCAN_UNIT_COUNT,
        )
    except ValueError:
        return 1


def compute_scan_unit_count_list(values):
    """
    Count concrete scan units represented by a comma-separated job target list.
    """
    total = 0
    for value in str(values or "").split(","):
        value = value.strip()
        if value:
            total = min(total + compute_scan_unit_count(value), MAX_SCAN_UNIT_COUNT)
    return max(total, 1)


def scalar(db_cursor, sql, params=None):
    """
    Return the first column from one SQL row, or zero.
    """
    db_cursor.execute(sql, params or {})
    row = db_cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


def profile_target_filter(apply_to_all):
    """
    SQL condition selecting targets applicable to a profile.
    """
    if apply_to_all:
        return ""
    return """
       AND EXISTS (
            SELECT 1
              FROM scanprofiles_targets_assoc AS spta
             WHERE spta.scanprofile_id = sc.scanprofile_id
               AND spta.target_id = tss.target_id
       )
    """


def backfill_targets(db_cursor):
    """
    Backfill target scan-unit counters.
    """
    db_cursor.execute("SELECT id, value FROM targets")
    rows = db_cursor.fetchall()
    db_cursor.executemany(
        "UPDATE targets SET scan_unit_count = ? WHERE id = ?",
        [(compute_scan_unit_count(value), target_id) for target_id, value in rows],
    )


def backfill_jobs(db_cursor):
    """
    Backfill job scan-unit counters from stored job values.
    """
    db_cursor.execute("SELECT id, job FROM jobs")
    rows = db_cursor.fetchall()
    db_cursor.executemany(
        "UPDATE jobs SET scan_unit_count = ? WHERE id = ?",
        [(compute_scan_unit_count_list(job), job_id) for job_id, job in rows],
    )


def backfill_cycles(db_cursor):
    """
    Backfill cycle totals from target states and finished jobs.
    """
    db_cursor.execute("""
        SELECT sc.id,
               sc.scanprofile_id,
               sc.started_at,
               sc.status,
               sp.apply_to_all,
               COALESCE(sc.completed_scan_unit_count, 0)
          FROM scanprofile_cycles AS sc
          JOIN scanprofiles AS sp ON sp.id = sc.scanprofile_id
    """)
    cycles = db_cursor.fetchall()

    for (
        cycle_id,
        _profile_id,
        started_at,
        status,
        apply_to_all,
        stored_completed,
    ) in cycles:
        target_filter = profile_target_filter(bool(apply_to_all))
        total = scalar(
            db_cursor,
            f"""
            SELECT COALESCE(SUM(t.scan_unit_count), 0)
              FROM target_scan_states AS tss
              JOIN targets AS t ON t.id = tss.target_id
              JOIN scanprofile_cycles AS sc ON sc.id = :cycle_id
             WHERE tss.scanprofile_id = sc.scanprofile_id
               AND t.active = 1
               {target_filter}
            """,
            {"cycle_id": cycle_id},
        )
        completed_targets = scalar(
            db_cursor,
            f"""
            SELECT COUNT(tss.id)
              FROM target_scan_states AS tss
              JOIN targets AS t ON t.id = tss.target_id
              JOIN scanprofile_cycles AS sc ON sc.id = :cycle_id
             WHERE tss.scanprofile_id = sc.scanprofile_id
               AND t.active = 1
               AND tss.working = 0
               AND tss.last_scan IS NOT NULL
               AND tss.last_scan >= :started_at
               {target_filter}
            """,
            {"cycle_id": cycle_id, "started_at": started_at or ""},
        )
        completed_by_state = scalar(
            db_cursor,
            f"""
            SELECT COALESCE(SUM(t.scan_unit_count), 0)
              FROM target_scan_states AS tss
              JOIN targets AS t ON t.id = tss.target_id
              JOIN scanprofile_cycles AS sc ON sc.id = :cycle_id
             WHERE tss.scanprofile_id = sc.scanprofile_id
               AND t.active = 1
               AND tss.working = 0
               AND tss.last_scan IS NOT NULL
               AND tss.last_scan >= :started_at
               {target_filter}
            """,
            {"cycle_id": cycle_id, "started_at": started_at or ""},
        )
        completed_by_jobs = scalar(
            db_cursor,
            """
            SELECT COALESCE(SUM(scan_unit_count), 0)
              FROM jobs
             WHERE scanprofile_cycle_id = :cycle_id
               AND finished = 1
            """,
            {"cycle_id": cycle_id},
        )
        completed = max(
            int(stored_completed or 0),
            int(completed_by_state or 0),
            int(completed_by_jobs or 0),
        )
        if total:
            completed = min(completed, total)
        if status == "finished":
            completed = total

        db_cursor.execute(
            """
            UPDATE scanprofile_cycles
               SET scan_unit_count = :total,
                   completed_scan_unit_count = :completed,
                   completed_target_count = :completed_targets
             WHERE id = :cycle_id
            """,
            {
                "total": total,
                "completed": completed,
                "completed_targets": completed_targets,
                "cycle_id": cycle_id,
            },
        )


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("PRAGMA foreign_keys=ON")

if not column_exists(cursor, "targets", "scan_unit_count"):
    cursor.execute(
        "ALTER TABLE targets ADD COLUMN scan_unit_count INTEGER NOT NULL DEFAULT 1"
    )

if not column_exists(cursor, "jobs", "scan_unit_count"):
    cursor.execute(
        "ALTER TABLE jobs ADD COLUMN scan_unit_count INTEGER NOT NULL DEFAULT 1"
    )

if not column_exists(cursor, "scanprofile_cycles", "scan_unit_count"):
    cursor.execute(
        "ALTER TABLE scanprofile_cycles ADD COLUMN scan_unit_count INTEGER NOT NULL DEFAULT 0"
    )

if not column_exists(cursor, "scanprofile_cycles", "completed_scan_unit_count"):
    cursor.execute(
        "ALTER TABLE scanprofile_cycles ADD COLUMN completed_scan_unit_count INTEGER NOT NULL DEFAULT 0"
    )

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_jobs_scanprofile_cycle_finished
        ON jobs(scanprofile_cycle_id, finished)
""")

backfill_targets(cursor)
backfill_jobs(cursor)
backfill_cycles(cursor)

conn.commit()
conn.close()

print("Scan profile scan-unit migration complete")
