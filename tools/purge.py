#!/usr/bin/env python3
"""Purge indexed captures older than a given last_seen age.

The OUT_* settings in tools/config.yaml select both indexes. Finish pending
exports and stop index writers before running this tool. For managed indexes,
run from the controller's installation so its journal and locks are shared.
The job archive has its own retention policy.
"""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import sys
import time

from meilisearch import Client
from meilisearch.errors import MeilisearchError
from redis.exceptions import RedisError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from yaml import YAMLError

ROOT = Path(__file__).resolve().parents[1]
WEBAPP = ROOT / "webapp"
CONFIG_PATH = ROOT / "tools/config.yaml"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(WEBAPP))
sys.path.insert(0, str(WEBAPP / "app/utils"))

# pylint: disable=wrong-import-position
from index_generations import ACTIVE, CONTROL, GenerationClient, file_lock
from index_reconciliation import delete_capture, state_directory
from kvrocks import KVrocksIndexer
from plum_settings import tool_configuration
from tools.lib.config import load_yaml_config, require_config_values

# pylint: enable=wrong-import-position

BATCH_SIZE = 500
SECONDS_PER_DAY = 86_400


class PurgeError(RuntimeError):
    """Explain a purge precondition or a rejected deletion."""


def retention_days(value):
    """Accept a positive whole number of days followed by d."""
    try:
        if re.fullmatch(r"[0-9]+d", value) and (days := int(value[:-1])) > 0:
            return days
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("expected a positive number of days, e.g. 30d")


def parse_args(argv=None):
    """Require the exact deletion switch before opening the backends."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--keep",
        required=True,
        type=retention_days,
        metavar="XXd",
        help="keep captures seen within this number of days, e.g. 90d",
    )
    parser.add_argument(
        "--yes-delete-data",
        action="store_true",
        required=True,
        help="confirm permanent deletion from Meilisearch and the active Kvrocks index",
    )
    return parser.parse_args(argv)


def open_out_backends(settings):
    """Select only the explicitly configured OUT indexes."""
    if not isinstance(settings, dict):
        raise PurgeError("tools/config.yaml must contain a mapping.")
    try:
        url, host, port = require_config_values(
            settings,
            ("OUT_MEILI_URL", "OUT_KVROCKS_HOST", "OUT_KVROCKS_PORT"),
            CONFIG_PATH,
        )
    except KeyError as error:
        raise PurgeError(error.args[0]) from error
    raw = KVrocksIndexer(host, int(port), socket_timeout=30).raw
    meili = Client(url, settings.get("OUT_MEILI_API_KEY"), timeout=30).index(
        settings.get("INDEX_NAME", "plum")
    )
    return raw, meili


def managed_job_database(settings):
    """Find the job queue that can still write to the selected managed OUT."""
    import config  # pylint: disable=import-outside-toplevel,import-error

    applied = tool_configuration(config)
    matches_controller = (
        settings["OUT_KVROCKS_HOST"] == applied["KVROCKS_HOST"]
        and int(settings["OUT_KVROCKS_PORT"]) == int(applied["KVROCKS_PORT"])
        and settings["OUT_MEILI_URL"].rstrip("/")
        == applied["MEILI_DATABASE_URI"].rstrip("/")
        and settings.get("INDEX_NAME", "plum") == "plum"
    )
    if not matches_controller:
        raise PurgeError(
            "Managed OUT endpoints must match this controller's active indexes."
        )
    return applied["SQLALCHEMY_DATABASE_URI"]


def has_pending_exports(database_uri):
    """Check durable job state, including successful Meili tasks awaiting Kvrocks."""
    url = make_url(database_uri)
    statement = (
        "SELECT 1 FROM jobs WHERE finished IS TRUE AND exported IS NOT TRUE LIMIT 1"
    )
    if url.get_backend_name() == "sqlite":
        if not url.database or url.database == ":memory:":
            raise PurgeError("The controller needs a persistent job database.")
        database = (WEBAPP / "app" / url.database).resolve(strict=True)
        with closing(
            sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        ) as connection:
            return connection.execute(statement).fetchone() is not None
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return connection.execute(text(statement)).first() is not None
    finally:
        engine.dispose()


def require_idle_exports(raw, meili, database_uri):
    """Refuse when either backend still has an unfinished export."""
    if raw.zcount(CONTROL + "activity:ingestion", time.time(), "+inf"):
        raise PurgeError(
            "Index ingestion is active. Stop the controller before purging."
        )
    if database_uri is not None and has_pending_exports(database_uri):
        raise PurgeError("Finish exporting scanner jobs before purging.")
    tasks = meili.get_tasks({"statuses": ["enqueued", "processing"], "limit": 1})
    if tasks.results:
        raise PurgeError("Wait for pending Meilisearch tasks before purging.")


def purge_documents(raw, meili, cutoff, *, batch_size=BATCH_SIZE):
    """Delete aged UIDs from Meili before their Kvrocks entry and journal."""
    current = GenerationClient(raw)
    deleted = 0
    while uids := current.zrangebyscore(
        "last_seen_index", 0, f"({cutoff}", start=0, num=batch_size
    ):
        task = meili.delete_documents(uids)
        result = meili.wait_for_task(
            task.task_uid, timeout_in_ms=60_000, interval_in_ms=500
        )
        if result.status != "succeeded":
            raise PurgeError(
                f"Meilisearch deletion task {task.task_uid} did not succeed."
            )
        for uid in uids:
            delete_capture(raw, uid)
            deleted += 1
        print(f"Purged {deleted} captures", flush=True)
    return deleted


def main(argv=None):
    """Run administrative retention against the configured OUT indexes."""
    args = parse_args(argv)
    cutoff = int(time.time()) - args.keep * SECONDS_PER_DAY
    if cutoff <= 0:
        print("No captures can precede the requested retention cutoff.")
        return 0

    try:
        settings = load_yaml_config(CONFIG_PATH)
        raw, meili = open_out_backends(settings)
        managed = any(raw.mget((ACTIVE, CONTROL + "desired", CONTROL + "job")))
        database_uri = managed_job_database(settings) if managed else None
        lock_name = "worker.lock" if managed else "purge.lock"
        with file_lock(state_directory() / lock_name, blocking=False):
            require_idle_exports(raw, meili, database_uri)
            print(
                f"Purging last_seen before {datetime.fromtimestamp(cutoff, timezone.utc).isoformat()}"
            )
            deleted = purge_documents(raw, meili, cutoff)
    except KeyboardInterrupt:
        print("Purge interrupted. Rerun before resuming exports.", file=sys.stderr)
        return 130
    except BlockingIOError:
        print(
            "An index worker or another purge holds the maintenance lock.",
            file=sys.stderr,
        )
        return 1
    except PurgeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        KeyError,
        ValueError,
        OSError,
        YAMLError,
        sqlite3.Error,
        SQLAlchemyError,
        MeilisearchError,
        RedisError,
    ) as error:
        print(
            f"Purge stopped ({type(error).__name__}). Resolve the failure and rerun before resuming exports.",
            file=sys.stderr,
        )
        return 1
    print(f"Done. Purged {deleted} captures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
