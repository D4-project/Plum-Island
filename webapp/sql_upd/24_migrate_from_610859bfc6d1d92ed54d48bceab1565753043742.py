"""Migration 24: persist Targets.is_ip_cidr without changing stored values.

Stop application writers first. --dry-run uses a memory copy.
Backups are managed by the operator, not by this script.
Invalid target syntax aborts the whole transaction, reporting target IDs only.
"""

# pylint: disable=invalid-name
import argparse
from pathlib import Path
import sqlite3
import sys

# Import shared helpers without starting Flask or the scheduler.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "utils"))
from mutils import classify_target_is_ip_cidr  # pylint: disable=wrong-import-position

DB_PATH = Path(__file__).resolve().parents[1] / "app.db"


def migrate(connection):
    """Validate all rows first; caller owns the atomic transaction."""
    rows = []
    invalid_ids = []
    for target_id, value in connection.execute(
        "SELECT id, value FROM targets ORDER BY id"
    ):
        try:
            rows.append((int(classify_target_is_ip_cidr(value)), target_id))
        except ValueError:
            invalid_ids.append(target_id)
    if invalid_ids:
        raise ValueError(f"Unclassifiable target IDs: {invalid_ids}")
    columns = {row[1]: row for row in connection.execute("PRAGMA table_info(targets)")}
    if "is_ip_cidr" not in columns:
        connection.execute(
            "ALTER TABLE targets ADD COLUMN is_ip_cidr BOOLEAN NOT NULL DEFAULT 0 "
            "CHECK (is_ip_cidr IN (0, 1))"
        )
    elif not columns["is_ip_cidr"][3]:
        raise ValueError(
            "Existing is_ip_cidr column is nullable; manual schema review required"
        )
    before = connection.total_changes
    connection.executemany(
        "UPDATE targets SET is_ip_cidr = ? WHERE id = ? AND is_ip_cidr IS NOT ?",
        [(flag, target_id, flag) for flag, target_id in rows],
    )
    return {
        "targets": len(rows),
        "ip_cidr": sum(flag for flag, _ in rows),
        "fqdn": sum(not flag for flag, _ in rows),
        "updated": connection.total_changes - before,
    }


def main():
    """Apply atomically; never create a missing source database."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    mode = "ro" if args.dry_run else "rw"
    with sqlite3.connect(
        f"{args.db.resolve().as_uri()}?mode={mode}", uri=True
    ) as source:
        connection = source
        if args.dry_run:
            connection = sqlite3.connect(":memory:")
            source.backup(connection)
        try:
            connection.execute("BEGIN IMMEDIATE")
            summary = migrate(connection)
            connection.commit()
            print(f"{'DRY RUN' if args.dry_run else 'Migrated'}: {summary}")
        except Exception:
            connection.rollback()
            raise
        finally:
            if connection is not source:
                connection.close()
    source.close()


if __name__ == "__main__":
    main()
