"""Enforce unique scan profile names without renaming profiles or changing IDs."""

# pylint: disable=invalid-name

import argparse
from pathlib import Path
import sqlite3


def migrate(connection):
    """Refuse ambiguous names before creating the index."""
    duplicates = connection.execute(
        "SELECT group_concat(id) FROM scanprofiles GROUP BY name HAVING count(*) > 1"
    ).fetchall()
    if duplicates:
        groups = "; ".join(row[0] for row in duplicates)
        raise ValueError(f"Rename duplicate scan profiles with these IDs: {groups}")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_scanprofiles_name ON scanprofiles(name)"
    )
    indexes = connection.execute("PRAGMA index_list(scanprofiles)").fetchall()
    columns = connection.execute("PRAGMA index_info(ix_scanprofiles_name)").fetchall()
    if not any(
        index[1] == "ix_scanprofiles_name" and index[2] and not index[4]
        for index in indexes
    ) or [column[2] for column in columns] != ["name"]:
        raise ValueError("Existing ix_scanprofiles_name has an incompatible definition")


def main():
    """Apply to an existing SQLite database under one write transaction."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    with sqlite3.connect(args.db.resolve().as_uri() + "?mode=rw", uri=True) as conn:
        conn.execute("BEGIN IMMEDIATE")
        migrate(conn)
        if args.dry_run:
            conn.rollback()


if __name__ == "__main__":
    main()
