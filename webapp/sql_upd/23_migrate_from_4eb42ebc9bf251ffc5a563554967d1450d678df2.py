"""Migration 23: shared AS enrichment and target insertion timestamps.

Standalone SQLite migration: no Flask startup or external service calls.
Supply --history-csv to include retained first_seen history beyond SQL jobs.
"""

# pylint: disable=invalid-name
import argparse
import csv
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import sqlite3

DB_PATH = Path(__file__).resolve().parent.parent / "app.db"
TARGET_COLUMNS = {
    "created_at": "DATETIME",
    "network_asn": "BIGINT REFERENCES autonomous_systems(asn)",
    "network_updated_at": "DATETIME",
    "network_refresh_pending": "BOOLEAN NOT NULL DEFAULT 0",
    "network_retry_at": "DATETIME",
    "network_claim": "VARCHAR(36)",
    "network_claim_until": "DATETIME",
}


def timestamp(value):
    """Normalize CSV/SQLite dates to naive UTC, including epoch seconds."""
    if value in (None, ""):
        return None
    try:
        result = datetime.fromtimestamp(float(value), timezone.utc)
    except (ValueError, TypeError):
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is not None:
        result = result.astimezone(timezone.utc).replace(tzinfo=None)
    return result


def columns(connection, table):
    """Inspect a fixed internal table name, never a CLI SQL identifier."""
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _remember(dates, target_id, value):
    date = timestamp(value)
    if date is not None and (target_id not in dates or date < dates[target_id]):
        dates[target_id] = date


def sql_history(connection):
    """Collect earliest surviving scan evidence; never use job creation time."""
    dates = {}
    for table, key in (("targets", "id"), ("target_scan_states", "target_id")):
        available = columns(connection, table)
        for field in ("last_scan", "last_previous_scan"):
            if field in available:
                for target_id, date in connection.execute(
                    f"SELECT {key}, MIN({field}) FROM {table} "
                    f"WHERE {field} IS NOT NULL GROUP BY {key}"
                ):
                    _remember(dates, target_id, date)
    available = columns(connection, "jobs")
    if {"id", "finished", "job_start", "job_end"} <= available and columns(
        connection, "jobs_targets_assoc"
    ):
        for target_id, date in connection.execute(
            "SELECT a.target_id, MIN(COALESCE(j.job_start, j.job_end)) "
            "FROM jobs j JOIN jobs_targets_assoc a ON a.job_id = j.id "
            "WHERE j.finished = 1 GROUP BY a.target_id"
        ):
            _remember(dates, target_id, date)
    return dates


def _history_target_index(connection):
    """Index only existing prefix lengths, avoiding all-target scans per row."""
    exact = {}
    networks = {4: {}, 6: {}}
    for target_id, value in connection.execute("SELECT id, value FROM targets"):
        exact[value.lower().rstrip(".")] = target_id
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        by_prefix = networks[network.version].setdefault(network.prefixlen, {})
        by_prefix.setdefault(int(network.network_address), []).append(target_id)
    return exact, networks


def _matching_history_targets(row, exact, networks):
    """Yield exact requested targets or containing ranges for IP observations."""
    value = (row.get("target") or row.get("ip") or "").strip()
    target_id = exact.get(value.lower().rstrip("."))
    if target_id is not None:
        yield target_id
    if row.get("target"):
        return
    address = ipaddress.ip_address(value)
    bits = address.max_prefixlen
    for prefix, by_address in networks[address.version].items():
        start = (int(address) >> (bits - prefix)) << (bits - prefix)
        yield from by_address.get(start, [])


def add_csv_history(connection, dates, csv_path):
    """Match exported IP history to CIDRs and explicit target values to FQDNs."""
    exact, networks = _history_target_index(connection)
    with Path(csv_path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        if "first_seen" not in fields or not fields.intersection({"target", "ip"}):
            raise ValueError("History CSV requires first_seen and target or ip columns")
        for number, row in enumerate(reader, start=2):
            try:
                date = timestamp(row.get("first_seen"))
                if date is None:
                    continue
                for target_id in _matching_history_targets(row, exact, networks):
                    _remember(dates, target_id, date.isoformat())
            except (ValueError, OverflowError, OSError) as error:
                raise ValueError(f"Invalid history CSV row {number}") from error


def migrate(connection, now=None, history_csv=None):
    """Migrate within the caller's transaction; preserve populated timestamps."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    dates = sql_history(connection)
    if history_csv:
        add_csv_history(connection, dates, history_csv)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS autonomous_systems (
            asn BIGINT PRIMARY KEY NOT NULL, name VARCHAR(512) NOT NULL,
            country_alpha2 VARCHAR(2), country_alpha3 VARCHAR(3),
            country_numeric VARCHAR(3), latitude FLOAT, longitude FLOAT,
            updated_at DATETIME NOT NULL
        )
    """)
    existing = columns(connection, "targets")
    for name, definition in TARGET_COLUMNS.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE targets ADD COLUMN {name} {definition}")
    summary = {"history": 0, "fallback_now": 0, "preserved": 0, "legacy_as": 0}
    targets = connection.execute("SELECT id, value, created_at FROM targets").fetchall()
    for target_id, value, created_at in targets:
        if created_at is not None:
            summary["preserved"] += 1
            continue
        date = dates.get(target_id, now)
        summary["history" if target_id in dates else "fallback_now"] += 1
        connection.execute(
            "UPDATE targets SET created_at = ? WHERE id = ?", (date, target_id)
        )
        if {"as_bgp", "as_description", "as_country"} <= existing:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            asn, name, country = connection.execute(
                "SELECT as_bgp, as_description, as_country FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if not asn or not 0 < int(asn) <= 4294967295:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO autonomous_systems "
                "(asn, name, country_alpha2, updated_at) VALUES (?, ?, ?, ?)",
                (asn, name or "Unknown (legacy)", country, now),
            )
            connection.execute(
                "UPDATE targets SET network_asn = ? WHERE id = ?", (asn, target_id)
            )
            summary["legacy_as"] += 1
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_targets_network_asn ON targets(network_asn)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_targets_network_pending "
        "ON targets(network_refresh_pending, network_retry_at, id)"
    )
    return summary


def main():
    """Dry-run uses a memory copy, keeping the specified database untouched."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--history-csv", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    mode = "ro" if args.dry_run else "rw"
    source = sqlite3.connect(f"{args.db.resolve().as_uri()}?mode={mode}", uri=True)
    connection = source
    if args.dry_run:
        connection = sqlite3.connect(":memory:")
        source.backup(connection)
        source.close()
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN")
        summary = migrate(connection, history_csv=args.history_csv)
        connection.commit()
        print(f"{'DRY RUN' if args.dry_run else 'Migrated'}: {summary}")
        print(
            "Dates use the oldest AVAILABLE scan evidence. Purged history cannot "
            "be reconstructed; supplement with --history-csv before migration."
        )
        print("Existing targets are enriched on their next scan or manual refresh.")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    main()
