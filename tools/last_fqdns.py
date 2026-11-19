#!/usr/bin/env python3
"""
Extract from the kvrocks DB the latest FQDNS
This tool may resolve directly for PDNS accounting.
"""

# pylint: disable=import-error,wrong-import-position,broad-exception-caught

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lib.config import (
    load_yaml_config,
    plum_credentials_from_config,
    require_config_values,
)
from lib.dns import count_resolved, is_ipv4_address, resolve_fqdns
from lib.iterables import chunk_items
from lib.plum_api import bulk_import_targets, get_access_token
from lib.tool_logging import get_logger, setup_logger as setup_tool_logger

THIS_DIR = Path(__file__).resolve().parent
CONFIG_PATH = THIS_DIR / "config.yaml"
LOG_DIR = THIS_DIR / "log"
CHUNK_SIZE = 150
RESOLVE_PROGRESS_INTERVAL = 100

sys.path.append(str(THIS_DIR.parent / "webapp" / "app" / "utils"))
from kvrocks import KVrocksIndexer  # noqa: E402

logger = get_logger()


def setup_logger(debug=False):
    """
    Configure Rich console logging and the persistent daily-rotated log file.
    """
    return setup_tool_logger(LOG_DIR / "last_fqdns.log", debug=debug, logger=logger)


def load_config():
    """
    Load tool settings from tools/config.yaml.
    """
    config = load_yaml_config(CONFIG_PATH)
    require_config_values(
        config,
        ("OUT_KVROCKS_HOST", "OUT_KVROCKS_PORT"),
        CONFIG_PATH,
    )
    return config


def load_plum_config(config):
    """
    Load Plum API settings from config.yaml.
    """
    return plum_credentials_from_config(config, CONFIG_PATH)


def compile_learn_regexes(config):
    """
    Compile configured FQDN learn regexes as case-insensitive expressions.
    """
    configured = config.get("last_fqdns_learn") or []
    if isinstance(configured, str):
        configured = [configured]
    if not isinstance(configured, list):
        raise ValueError(f"last_fqdns_learn must be a list in {CONFIG_PATH}")

    regexes = []
    for pattern in configured:
        pattern = str(pattern).strip()
        if not pattern:
            continue
        try:
            regexes.append(re.compile(pattern, re.IGNORECASE))
        except re.error as error:
            logger.warning("Invalid learn regex skipped %r: %s", pattern, error)
    return regexes


def log_fqdns(filtered):
    """
    Log FQDN output without writing to stdout.
    """
    for fqdn in filtered:
        logger.debug("Found FQDN: %s", fqdn)


def learn_fqdns(config, filtered, resolutions=None):
    """
    Import resolved FQDNs matching configured regexes into Plum targets.
    """
    regexes = compile_learn_regexes(config)
    if not regexes:
        logger.warning("Learn enabled but last_fqdns_learn has no valid regex")
        return 0

    candidates = [
        fqdn for fqdn in filtered if any(regex.search(fqdn) for regex in regexes)
    ]
    logger.info("Learn regex matched FQDN count: %d", len(candidates))
    if not filtered:
        return 0

    if resolutions is None:
        resolutions = resolve_fqdns(
            filtered,
            workers=25,
            progress_interval=RESOLVE_PROGRESS_INTERVAL,
            logger=logger,
        )

    if not candidates:
        return 0

    learned = [
        fqdn for fqdn in candidates if resolutions.get(fqdn, {}).get("addresses")
    ]
    logger.info("Learn resolved FQDN count: %d", len(learned))
    if not learned:
        return 0

    base_url, username, password = load_plum_config(config)
    token = get_access_token(base_url, username, password)

    created_count = 0
    for chunk_index, chunk in enumerate(chunk_items(learned, CHUNK_SIZE), start=1):
        result = bulk_import_targets(base_url, token, "\n".join(chunk))
        chunk_created_count = count_created_targets(result)
        created_count += chunk_created_count
        logger.info(
            "Learn import chunk %d submitted=%d created=%d",
            chunk_index,
            len(chunk),
            chunk_created_count,
        )
        logger.debug("Learn import chunk %d result: %s", chunk_index, result)
    return created_count


def count_created_targets(result):
    """
    Count newly created targets from the API bulk-import response log.
    """
    message = result.get("message", {}) if isinstance(result, dict) else {}
    log_lines = message.get("log", []) if isinstance(message, dict) else []
    return sum(
        1
        for line in log_lines
        if line.endswith(" FQDN Processed") or line.endswith(" Processed")
    )


def log_summary(found_count, resolved_count, plum_imported_count):
    """
    Log final stats for the run.
    """
    logger.info("FQDN found: %d", found_count)
    logger.info("FQDN resolved: %d", resolved_count)
    logger.info("New FQDN in Plum: %d", plum_imported_count)


def main():
    """
    Output unique FQDNs observed during the requested time window.
    """
    parser = argparse.ArgumentParser(
        description="Output unique FQDNs observed during the last N hours (default: 24h)."
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Time window (in hours) used to filter last_seen timestamps.",
    )
    parser.add_argument(
        "--resolve",
        choices=["yes", "no"],
        default="no",
        help="Resolve each found FQDN (default: no).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show debug logs on console, including each FQDN resolution",
    )
    parser.add_argument(
        "--learn",
        action="store_true",
        help="import resolved FQDNs matching last_fqdns_learn regexes into Plum",
    )
    args = parser.parse_args()
    setup_logger(debug=args.debug)

    if args.hours <= 0:
        parser.error("--hours must be a positive integer")

    cutoff_ts = int(
        (datetime.now(tz=timezone.utc) - timedelta(hours=args.hours)).timestamp()
    )

    config = load_config()
    kvrocks_host = config["OUT_KVROCKS_HOST"]
    kvrocks_port = config["OUT_KVROCKS_PORT"]
    logger.info(
        "Read FQDNs from Kvrocks %s:%s for last %d hours",
        kvrocks_host,
        kvrocks_port,
        args.hours,
    )
    indexer = KVrocksIndexer(kvrocks_host, kvrocks_port)
    redis_client = indexer.r

    uid_list = redis_client.zrevrangebyscore("last_seen_index", "+inf", cutoff_ts)
    logger.info("UID count: %d", len(uid_list))
    unique_fqdns = set()
    for uid in uid_list:
        unique_fqdns.update(redis_client.smembers(f"fqdns:{uid}"))

    filtered = sorted(
        fqdn for fqdn in unique_fqdns if fqdn and not is_ipv4_address(fqdn)
    )
    logger.info("Unique FQDN count: %d", len(filtered))

    resolutions = None
    plum_imported_count = 0
    if args.resolve == "yes":
        logger.info("Resolve FQDNs: yes")
        resolutions = resolve_fqdns(
            filtered,
            workers=25,
            progress_interval=RESOLVE_PROGRESS_INTERVAL,
            logger=logger,
        )

    if args.learn:
        if resolutions is None:
            resolutions = resolve_fqdns(
                filtered,
                workers=25,
                progress_interval=RESOLVE_PROGRESS_INTERVAL,
                logger=logger,
            )
        plum_imported_count = learn_fqdns(config, filtered, resolutions=resolutions)

    log_fqdns(filtered)
    log_summary(len(filtered), count_resolved(resolutions), plum_imported_count)


if __name__ == "__main__":
    main()
