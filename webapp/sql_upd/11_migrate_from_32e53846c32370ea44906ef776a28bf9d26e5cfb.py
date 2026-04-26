import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def table_exists(cursor, table_name):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cursor.fetchone() is not None


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

if table_exists(cursor, "reports"):
    cursor.execute(
        """
        CREATE TABLE reports_new (
            id INTEGER NOT NULL,
            name VARCHAR(256) NOT NULL,
            active BOOLEAN NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            query TEXT NOT NULL,
            emails TEXT NOT NULL DEFAULT '',
            schedule_type VARCHAR(32) NOT NULL DEFAULT 'monthly',
            schedule_day INTEGER NOT NULL DEFAULT 1,
            schedule_hour INTEGER NOT NULL DEFAULT 8,
            last_run_at DATETIME,
            next_run_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE (name)
        )
        """
    )
    cursor.execute(
        """
        INSERT INTO reports_new (
            id,
            name,
            active,
            description,
            query,
            emails,
            schedule_type,
            schedule_day,
            schedule_hour,
            last_run_at,
            next_run_at,
            created_at,
            updated_at
        )
        SELECT
            id,
            name,
            active,
            description,
            query,
            emails,
            schedule_type,
            schedule_day,
            schedule_hour,
            last_run_at,
            next_run_at,
            created_at,
            updated_at
        FROM reports
        """
    )
    cursor.execute("DROP TABLE reports")
    cursor.execute("ALTER TABLE reports_new RENAME TO reports")
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_reports_name_unique ON reports(name)"
    )

conn.commit()
conn.close()

print("Reports active default migration complete")
