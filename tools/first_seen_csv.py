#!/usr/bin/env python3
"""
Export and restore Kvrocks first_seen values.

first_seen is historical state accumulated in Kvrocks. It is not fully
reparsable from Meilisearch/Nmap documents, so this tool can preserve it across
rebuilds.
"""

import argparse
import csv
from pathlib import Path
import sys

import redis
import yaml

BASE_DIR = Path(__file__).resolve().parent
WEBAPP_UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(WEBAPP_UTILS_DIR))

from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position

CONFIG_PATH = BASE_DIR / "config.yaml"
CSV_FIELDS = ["uid", "ip", "first_seen", "last_seen"]


def load_config():
    """
    Load shared tools configuration.
    """
    with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def connect_kvrocks(config, prefix):
    """
    Connect to Kvrocks using IN_* or OUT_* configuration keys.
    """
    prefix = prefix.upper()
    host = config.get(f"{prefix}_KVROCKS_HOST")
    port = config.get(f"{prefix}_KVROCKS_PORT")
    if host in (None, "") or port in (None, ""):
        raise SystemExit(
            f"Missing {prefix}_KVROCKS_HOST/{prefix}_KVROCKS_PORT in {CONFIG_PATH}"
        )
    return redis.Redis(host=host, port=int(port), decode_responses=True, db=0)


def parse_args():
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Export or restore Kvrocks first_seen values as CSV."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--export",
        metavar="CSV_FILE",
        help="Export first_seen values from IN_KVROCKS_* to a CSV file.",
    )
    mode.add_argument(
        "--import",
        dest="import_file",
        metavar="CSV_FILE",
        help="Import first_seen values from a CSV file into OUT_KVROCKS_*.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="SCAN/pipeline batch size. Default: 1000.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate import CSV without writing to OUT_KVROCKS_*.",
    )
    return parser.parse_args()


def iter_doc_keys(redis_client, batch_size):
    """
    Iterate doc keys and return their UID.
    """
    for key in redis_client.scan_iter(match="doc:*", count=batch_size):
        uid = key.split("doc:", 1)[1].strip()
        if uid:
            yield key, uid


def count_doc_keys(redis_client, batch_size):
    """
    Count doc keys for progress reporting.
    """
    return sum(1 for _key in redis_client.scan_iter(match="doc:*", count=batch_size))


def count_csv_rows(csv_path):
    """
    Count data rows in a CSV file for progress reporting.
    """
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return max(sum(1 for _line in handle) - 1, 0)


def export_first_seen(redis_client, csv_file, batch_size):
    """
    Export doc:{uid} first_seen values from IN Kvrocks.
    """
    exported = 0
    skipped = 0
    csv_path = Path(csv_file)
    expected = count_doc_keys(redis_client, batch_size)
    print(f"Export expected: {expected}", file=sys.stderr)
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for key, uid in iter_doc_keys(redis_client, batch_size):
            data = redis_client.hgetall(key)
            first_seen = KVrocksIndexer.normalize_timestamp(data.get("first_seen"))
            last_seen = KVrocksIndexer.normalize_timestamp(data.get("last_seen"))
            if first_seen is None:
                skipped += 1
                continue
            writer.writerow(
                {
                    "uid": uid,
                    "ip": data.get("ip", ""),
                    "first_seen": first_seen,
                    "last_seen": "" if last_seen is None else last_seen,
                }
            )
            exported += 1
            if exported % 1000 == 0:
                print(
                    f"Export progress: exported={exported}/{expected} "
                    f"skipped={skipped}",
                    file=sys.stderr,
                )
    print(
        "Export complete: "
        f"expected={expected} exported={exported} skipped={skipped} file={csv_path}"
    )


def flush_import_batch(redis_client, rows, dry_run):
    """
    Apply one import batch to OUT Kvrocks.
    """
    if not rows:
        return {"updated": 0, "missing": 0}

    pipe = redis_client.pipeline(transaction=False)
    for row in rows:
        pipe.exists(f"doc:{row['uid']}")
    exists_values = pipe.execute()

    updated = 0
    missing = 0
    write_pipe = redis_client.pipeline(transaction=False)
    for row, exists in zip(rows, exists_values):
        if not exists:
            missing += 1
            continue
        updated += 1
        if dry_run:
            continue
        write_pipe.hset(f"doc:{row['uid']}", "first_seen", str(row["first_seen"]))
        write_pipe.zadd("first_seen_index", {row["uid"]: row["first_seen"]})

    if not dry_run:
        write_pipe.execute()
    return {"updated": updated, "missing": missing}


def import_first_seen(redis_client, csv_file, batch_size, dry_run=False):
    """
    Restore doc:{uid}.first_seen and first_seen_index from a CSV file.
    """
    csv_path = Path(csv_file)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    expected = count_csv_rows(csv_path)
    print(f"Import expected: {expected}", file=sys.stderr)
    updated = 0
    missing = 0
    invalid = 0
    processed = 0
    rows = []

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if "uid" not in (reader.fieldnames or []) or "first_seen" not in (
            reader.fieldnames or []
        ):
            raise ValueError("CSV must contain at least uid and first_seen columns")

        for row_number, row in enumerate(reader, start=2):
            processed += 1
            uid = str(row.get("uid") or "").strip()
            first_seen = KVrocksIndexer.normalize_timestamp(row.get("first_seen"))
            if not uid or first_seen is None:
                invalid += 1
                print(
                    f"SKIP row={row_number}: invalid uid/first_seen",
                    file=sys.stderr,
                )
                continue

            rows.append({"uid": uid, "first_seen": first_seen})
            if len(rows) >= batch_size:
                result = flush_import_batch(redis_client, rows, dry_run)
                updated += result["updated"]
                missing += result["missing"]
                rows = []
            if processed % 1000 == 0:
                print(
                    "Import progress: "
                    f"processed={processed}/{expected} updated={updated} missing={missing} "
                    f"invalid={invalid} dry_run={dry_run}",
                    file=sys.stderr,
                )

    result = flush_import_batch(redis_client, rows, dry_run)
    updated += result["updated"]
    missing += result["missing"]

    print(
        "Import complete: "
        f"expected={expected} processed={processed} updated={updated} "
        f"missing={missing} invalid={invalid} "
        f"dry_run={dry_run} file={csv_path}"
    )


def main():
    """
    CLI entrypoint.
    """
    args = parse_args()
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")

    config = load_config()
    if args.export:
        export_first_seen(
            connect_kvrocks(config, "IN"),
            args.export,
            args.batch_size,
        )
        return

    import_first_seen(
        connect_kvrocks(config, "OUT"),
        args.import_file,
        args.batch_size,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
