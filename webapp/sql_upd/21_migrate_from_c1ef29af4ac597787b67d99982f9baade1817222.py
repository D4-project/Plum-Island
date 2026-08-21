"""Persist in-flight Meilisearch export state on jobs."""

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
    """Add durable Meilisearch task and document-count state."""
    if not column_exists(db_cursor, "jobs", "meili_task_uid"):
        db_cursor.execute("ALTER TABLE jobs ADD COLUMN meili_task_uid INTEGER")
    if not column_exists(db_cursor, "jobs", "meili_documents_submitted"):
        db_cursor.execute(
            "ALTER TABLE jobs ADD COLUMN meili_documents_submitted "
            "INTEGER NOT NULL DEFAULT 0"
        )
    if not column_exists(db_cursor, "jobs", "meili_documents_total"):
        db_cursor.execute("ALTER TABLE jobs ADD COLUMN meili_documents_total INTEGER")

    db_cursor.execute(
        "UPDATE jobs SET meili_documents_submitted = 0 "
        "WHERE meili_documents_submitted IS NULL"
    )


def main():
    """Apply migration to application SQLite database."""
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    migrate(cursor)
    connection.commit()
    connection.close()
    print("Meilisearch export task state migration complete")


if __name__ == "__main__":
    main()
