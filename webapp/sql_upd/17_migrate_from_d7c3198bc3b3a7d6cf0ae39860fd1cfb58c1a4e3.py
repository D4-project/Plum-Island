"""
Create the feeder role for API-only target imports.

The role is intentionally narrow:
- POST /api/v1/publictargetsapi/ for import_whois_ranges.py
- POST /targets_api/bulk_import for import_fqdns.py fed by last_fqdns.py output
"""

# pylint: disable=invalid-name

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"
ROLE_NAME = "Feeder"
PERMISSIONS = (
    ("can_post", "PublicTargetsApi"),
    ("can_bulk_import", "TargetsApi"),
)


def get_or_create(db_cursor, table_name, name):
    """
    Return the row id for a named FAB table entry, creating it if missing.
    """
    db_cursor.execute(f"SELECT id FROM {table_name} WHERE name = ?", (name,))
    row = db_cursor.fetchone()
    if row:
        return row[0]

    db_cursor.execute(f"INSERT INTO {table_name} (name) VALUES (?)", (name,))
    return db_cursor.lastrowid


def get_or_create_permission_view(db_cursor, permission_name, view_menu_name):
    """
    Return the permission-view id, creating permission/view rows if needed.
    """
    permission_id = get_or_create(db_cursor, "ab_permission", permission_name)
    view_menu_id = get_or_create(db_cursor, "ab_view_menu", view_menu_name)

    db_cursor.execute(
        """
        SELECT id
          FROM ab_permission_view
         WHERE permission_id = ?
           AND view_menu_id = ?
        """,
        (permission_id, view_menu_id),
    )
    row = db_cursor.fetchone()
    if row:
        return row[0]

    db_cursor.execute(
        """
        INSERT INTO ab_permission_view (permission_id, view_menu_id)
        VALUES (?, ?)
        """,
        (permission_id, view_menu_id),
    )
    return db_cursor.lastrowid


def sync_feeder_role(db_cursor):
    """
    Create the feeder role and set exactly the import permissions it needs.
    """
    role_id = get_or_create(db_cursor, "ab_role", ROLE_NAME)
    permission_view_ids = [
        get_or_create_permission_view(db_cursor, permission, view_menu)
        for permission, view_menu in PERMISSIONS
    ]

    db_cursor.execute(
        "DELETE FROM ab_permission_view_role WHERE role_id = ?",
        (role_id,),
    )
    db_cursor.executemany(
        """
        INSERT OR IGNORE INTO ab_permission_view_role (permission_view_id, role_id)
        VALUES (?, ?)
        """,
        [(permission_view_id, role_id) for permission_view_id in permission_view_ids],
    )
    return len(permission_view_ids)


def main():
    """
    Run the feeder role migration.
    """
    conn = sqlite3.connect(DB_PATH)
    db_cursor = conn.cursor()
    db_cursor.execute("PRAGMA foreign_keys=ON")

    permission_count = sync_feeder_role(db_cursor)

    conn.commit()
    conn.close()

    print(f"Feeder role migration complete: permissions={permission_count}")


if __name__ == "__main__":
    main()
