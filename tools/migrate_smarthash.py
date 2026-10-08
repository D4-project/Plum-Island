#!/usr/bin/env python3
"""Rehash a complete Meilisearch dump, merging duplicate observation history.

Preparation reads source history from IN Kvrocks in tools/config.yaml by default.
Only --apply-out invokes the existing destructive OUT replacement importer.
"""

import argparse
import copy
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

import redis
from nmap2json import smarthash
import yaml

CONFIG_PATH = Path(__file__).resolve().with_name("config.yaml")

try:
    from .split_meili_dump_by_port import port_document_uuid, strip_port_hash
except ImportError:
    from split_meili_dump_by_port import port_document_uuid, strip_port_hash


def check_library():
    """Fail closed when the installed library lacks volatile-date masking."""
    for script, prefix in (
        ("banner", "220 mail ESMTP; "),
        ("banner", r"HTTP/1.1 400 Bad Request\0d\0aDate: "),
        ("banner", r"RTSP/1.0 400 Bad Request\x0d\x0aDate: "),
        ("http-headers", "Date: "),
    ):
        first = {
            "portid": "25",
            "scripts": [
                {"id": script, "output": prefix + "mon, 2 mar 2026 10:13:52 -0500"}
            ],
        }
        second = copy.deepcopy(first)
        second["scripts"][0]["output"] = prefix + "Tue, May 12 2026 10:15:46 GMT"
        original = copy.deepcopy(first)
        if smarthash.port_smart_hash(first) != smarthash.port_smart_hash(second):
            raise ValueError(
                "Installed nmap2json lacks date normalization; update it before migration"
            )
        if first != original:
            raise ValueError("Installed smarthash mutates raw reports")
    return str(Path(smarthash.__file__).resolve())


def timestamp(value):
    """Accept epoch seconds/milliseconds or ISO UTC dates, never invent now()."""
    if value is None or value == "" or isinstance(value, bool):
        raise ValueError("Missing observation timestamp")
    try:
        number = float(value)
    except (TypeError, ValueError):
        date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        number = date.timestamp()
    if not math.isfinite(number) or number < 0:
        raise ValueError("Invalid observation timestamp")
    if number > 1_000_000_000_000:
        number /= 1000
    return int(number)


def load_history(path, doc, client):
    """Read exact source-ID bounds; incomplete history aborts preparation."""
    if client is not None:
        data = client.hgetall(f"doc:{doc['id']}")
    else:
        with path.with_suffix(".time").open(encoding="utf-8") as handle:
            data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Observation history must be an object")
    first, last = timestamp(data.get("first_seen")), timestamp(data.get("last_seen"))
    if first > last:
        raise ValueError("first_seen exceeds last_seen")
    return first, last


def port_documents(doc):
    """Use library hash/established UUIDs without altering raw banner content."""
    if not isinstance(doc, dict) or not isinstance(doc.get("id"), str) or not doc["id"]:
        raise ValueError("Each source document needs a nonempty string id")
    body = doc.get("body")
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("ports"), list)
        or not body["ports"]
    ):
        raise ValueError("Each source document needs a nonempty body.ports list")
    ip = doc.get("ip") or body.get("addr")
    ipaddress.ip_address(ip)
    for port in body["ports"]:
        if not isinstance(port, dict) or not str(port.get("portid", "")).isdigit():
            raise ValueError("Invalid port object or portid")
        if not 0 <= int(port["portid"]) <= 65535:
            raise ValueError("Port outside 0..65535")
        hashed = copy.deepcopy(port)
        hashed["hsh256"] = smarthash.port_smart_hash(port, exclude_keys=["hsh256"])
        result = copy.deepcopy(doc)
        result["ip"] = ip
        result["id"] = port_document_uuid(ip, hashed)
        result["body"]["ports"] = [strip_port_hash(hashed)]
        result["body"]["hsh256"] = hashed["hsh256"]
        yield result


def merge_document(connection, doc, first, last):
    """Accumulate bounds on disk and select newest payload, independent of order."""
    observed = timestamp(doc["body"].get("endtime", last))
    # Preserve port key order: the library hashes its JSON serialization as-is.
    payload = json.dumps(doc, ensure_ascii=False)
    row = connection.execute(
        "SELECT observed, payload, first_seen, last_seen FROM reports WHERE uid=?",
        (doc["id"],),
    ).fetchone()
    if row:
        if (observed, payload) < (row[0], row[1]):
            observed, payload = row[0], row[1]
        first, last = min(first, row[2]), max(last, row[3])
    connection.execute(
        "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?)",
        (doc["id"], observed, payload, first, last),
    )


def read_documents(path):
    """Support individual objects and exported arrays; reject malformed entries."""
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list) and data:
        return data
    raise ValueError("Expected a document or nonempty document array")


def write_dump(connection, output):
    """Publish a fresh importable dump only after complete input validation."""
    output.mkdir(parents=True, exist_ok=False)
    for uid, payload, first, last in connection.execute(
        "SELECT uid, payload, first_seen, last_seen FROM reports ORDER BY uid"
    ):
        folder = output / uid[0]
        folder.mkdir(exist_ok=True)
        (folder / f"{uid}.json").write_text(payload, encoding="utf-8")
        (folder / f"{uid}.time").write_text(
            json.dumps({"first_seen": first, "last_seen": last}), encoding="utf-8"
        )
    # JSONL is intentionally not matched by the importer's *.json discovery.
    with (output / "uid-map.jsonl").open("w", encoding="utf-8") as handle:
        for old, new in connection.execute(
            "SELECT old_uid, new_uid FROM mapping ORDER BY old_uid, new_uid"
        ):
            handle.write(json.dumps({"old_uid": old, "new_uid": new}) + "\n")


def prepare(input_dir, output_dir, *, dry_run=False, client=None, work_dir=None):
    """Prepare only; never mutate external databases or existing directories."""
    library = check_library()
    source, output = Path(input_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError("Input directory does not exist")
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("Input and output directories must not overlap")
    if output.exists():
        raise ValueError("Output directory must not exist; use a fresh path")
    summary = {
        "source_documents": 0,
        "port_documents": 0,
        "unique_documents": 0,
        "merged_documents": 0,
    }
    with tempfile.TemporaryDirectory(prefix="plum-rehash-", dir=work_dir) as scratch:
        connection = sqlite3.connect(str(Path(scratch) / "work.sqlite"))
        try:
            connection.execute(
                "CREATE TABLE reports(uid TEXT PRIMARY KEY, observed INTEGER, "
                "payload TEXT, first_seen INTEGER, last_seen INTEGER)"
            )
            connection.execute(
                "CREATE TABLE mapping(old_uid TEXT, new_uid TEXT, PRIMARY KEY(old_uid, new_uid))"
            )
            progress_at = time.monotonic()
            for path in source.rglob("*.json"):
                if path.is_symlink():
                    raise ValueError("Symlink source documents are not supported")
                docs = read_documents(path)
                if client is None and len(docs) != 1:
                    raise ValueError(
                        "Array dumps require --kvrocks-host for per-ID history"
                    )
                for doc in docs:
                    # Validate shape before looking up its ID in history.
                    generated = port_documents(doc)
                    first_doc = next(generated)
                    first, last = load_history(path, doc, client)
                    for migrated in _with_first(first_doc, generated):
                        merge_document(connection, migrated, first, last)
                        connection.execute(
                            "INSERT OR IGNORE INTO mapping VALUES (?, ?)",
                            (doc["id"], migrated["id"]),
                        )
                        summary["port_documents"] += 1
                    summary["source_documents"] += 1
                    if summary["source_documents"] % 1000 == 0:
                        connection.commit()
                    if time.monotonic() - progress_at >= 5:
                        print(
                            f"Progress: source={summary['source_documents']} ports={summary['port_documents']}",
                            flush=True,
                        )
                        progress_at = time.monotonic()
            if not summary["source_documents"]:
                raise ValueError("No documents found; refusing empty migration")
            connection.commit()
            summary["unique_documents"] = connection.execute(
                "SELECT count(*) FROM reports"
            ).fetchone()[0]
            summary["merged_documents"] = (
                summary["port_documents"] - summary["unique_documents"]
            )
            if not dry_run:
                write_dump(connection, output)
                # Written last: absent marker means incomplete preparation.
                (output / "migration.manifest").write_text(
                    json.dumps(
                        {"status": "complete", "library": library, **summary}, indent=2
                    ),
                    encoding="utf-8",
                )
        finally:
            connection.close()
    return summary


def _with_first(first, remaining):
    """Yield the validated first port followed by the rest without buffering."""
    yield first
    yield from remaining


def main(argv=None):
    """Prepare, or explicitly prepare and replace the configured OUT indexes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument(
        "--output-dir", required=True, help="New directory, must not exist"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and count, without publishing a dump",
    )
    parser.add_argument(
        "--kvrocks-host",
        help="Override IN_KVROCKS_HOST from tools/config.yaml",
    )
    parser.add_argument(
        "--kvrocks-port", type=int, help="Override IN_KVROCKS_PORT from tools/config.yaml"
    )
    parser.add_argument(
        "--use-time-companions",
        action="store_true",
        help="Read source history from .time files instead of IN Kvrocks",
    )
    parser.add_argument(
        "--work-dir", help="Parent for temporary disk-backed deduplication DB"
    )
    parser.add_argument(
        "--apply-out",
        action="store_true",
        help="DESTRUCTIVE: replace configured OUT Meilisearch and rebuild OUT Kvrocks after preparation",
    )
    args = parser.parse_args(argv)
    if args.dry_run and args.apply_out:
        parser.error("--dry-run cannot be combined with --apply-out")
    if args.use_time_companions and (args.kvrocks_host or args.kvrocks_port):
        parser.error("--use-time-companions cannot be combined with Kvrocks overrides")
    client = None
    if not args.use_time_companions:
        with CONFIG_PATH.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file) or {}
        host = args.kvrocks_host or config.get("IN_KVROCKS_HOST")
        port = (
            args.kvrocks_port
            if args.kvrocks_port is not None
            else config.get("IN_KVROCKS_PORT")
        )
        if not host or not port:
            parser.error(f"Missing IN_KVROCKS_HOST or IN_KVROCKS_PORT in {CONFIG_PATH}")
        try:
            port = int(port)
        except (TypeError, ValueError):
            parser.error(f"Invalid IN_KVROCKS_PORT in {CONFIG_PATH}")
        if not 1 <= port <= 65535:
            parser.error(f"Invalid IN_KVROCKS_PORT in {CONFIG_PATH}")
        client = redis.Redis(
            host=host,
            port=port,
            password=config.get("IN_KVROCKS_PASSWORD") or None,
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=10,
        )
    try:
        summary = prepare(
            args.input_dir,
            args.output_dir,
            dry_run=args.dry_run,
            client=client,
            work_dir=args.work_dir,
        )
    finally:
        if client is not None:
            client.close()
    print(json.dumps(summary, sort_keys=True), flush=True)
    if args.apply_out:
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("reimport_port_dump.py")),
                "--areyousure_yes",
                "--input-dir",
                str(Path(args.output_dir).resolve()),
                "--meili-replace-mode",
                "swap",
            ],
            check=True,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ValueError,
        OSError,
        redis.RedisError,
        sqlite3.Error,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Migration failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
