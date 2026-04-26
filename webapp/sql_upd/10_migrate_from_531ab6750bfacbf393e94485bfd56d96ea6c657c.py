import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"


def table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cursor.fetchall()}


def add_column(cursor, table_name, column_name, ddl):
    if column_name in table_columns(cursor, table_name):
        return False
    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")
    return True


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER NOT NULL,
        name VARCHAR(256) NOT NULL,
        active BOOLEAN NOT NULL DEFAULT 1,
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

add_column(cursor, "reports", "active", "active BOOLEAN NOT NULL DEFAULT 1")
add_column(cursor, "reports", "description", "description TEXT NOT NULL DEFAULT ''")
add_column(cursor, "reports", "emails", "emails TEXT NOT NULL DEFAULT ''")
add_column(
    cursor,
    "reports",
    "schedule_type",
    "schedule_type VARCHAR(32) NOT NULL DEFAULT 'monthly'",
)
add_column(cursor, "reports", "schedule_day", "schedule_day INTEGER NOT NULL DEFAULT 1")
add_column(cursor, "reports", "schedule_hour", "schedule_hour INTEGER NOT NULL DEFAULT 8")
add_column(cursor, "reports", "last_run_at", "last_run_at DATETIME")
add_column(cursor, "reports", "next_run_at", "next_run_at DATETIME")
add_column(
    cursor,
    "reports",
    "created_at",
    "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
)
add_column(
    cursor,
    "reports",
    "updated_at",
    "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
)

cursor.execute(
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_reports_name_unique ON reports(name)"
)

conn.commit()
conn.close()

print("Reports migration complete")
