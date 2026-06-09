#!/usr/bin/env python3
"""
Extract from the kvrocks DB the latest FQDNS
This tool may resolve directly for PDNS accounting.
"""

# pylint: disable=import-error,wrong-import-position,broad-exception-caught

import argparse
import concurrent.futures
import ipaddress
import logging
import logging.handlers
import re
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from rich.logging import RichHandler

THIS_DIR = Path(__file__).resolve().parent
CONFIG_PATH = THIS_DIR / "config.yaml"
LOG_DIR = THIS_DIR / "log"
CHUNK_SIZE = 150
RESOLVE_PROGRESS_INTERVAL = 100

sys.path.append(str(THIS_DIR.parent / "webapp" / "app" / "utils"))
from kvrocks import KVrocksIndexer  # noqa: E402
from import_fqdns import bulk_import_targets, get_access_token  # noqa: E402

logger = logging.getLogger("Plum_Agent")
logger.setLevel(logging.DEBUG)


def setup_logger(debug=False):
    """
    Configure Rich console logging and the persistent daily-rotated log file.
    """
    if logger.handlers:
        return

    console_handler = RichHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    LOG_DIR.mkdir(exist_ok=True)
    file_handler = logging.handlers.TimedRotatingFileHandler(
        LOG_DIR / "last_fqdns.log",
        when="midnight",
        interval=1,
        backupCount=14,
        encoding="utf-8",
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="[%X]")
    )
    logger.addHandler(file_handler)


def load_config():
    """
    Load tool settings from tools/config.yaml.
    """
    with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    host = config.get("OUT_KVROCKS_HOST")
    port = config.get("OUT_KVROCKS_PORT")
    if not host or not port:
        raise KeyError(f"Missing OUT_KVROCKS_HOST/OUT_KVROCKS_PORT in {CONFIG_PATH}")
    return config


def load_plum_config(config):
    """
    Load Plum API settings from config.yaml.
    """
    missing = [
        name
        for name in ("PLUMISLAND", "PLUMAPIUSER", "PLUMAPIPWD")
        if not config.get(name)
    ]
    if missing:
        raise KeyError(f"Missing {', '.join(missing)} in {CONFIG_PATH}")

    return config["PLUMISLAND"], config["PLUMAPIUSER"], config["PLUMAPIPWD"]


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


def resolve_single_fqdn(fqdn):
    """
    Resolve a single FQDN using socket.getaddrinfo.
    """
    try:
        infos = socket.getaddrinfo(fqdn, None)
    except socket.gaierror as exc:
        return [], str(exc)
    except TimeoutError as exc:  # pragma: no cover - defensive
        return [], str(exc)

    addresses = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addresses.append(sockaddr[0])
    return sorted(set(addresses)), None


def resolve_fqdns(fqdns, workers=25):
    """
    Resolve a list of FQDNs concurrently using socket.getaddrinfo.
    """
    results = {}
    total = len(fqdns)
    resolved_count = 0
    failed_count = 0
    logger.info("Resolve FQDN count: %d", total)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(resolve_single_fqdn, fqdn): fqdn for fqdn in fqdns
        }
        for processed_count, future in enumerate(
            concurrent.futures.as_completed(future_map), start=1
        ):
            fqdn = future_map[future]
            try:
                addresses, error = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                addresses, error = [], str(exc)
                logger.debug("FQDN resolve worker failed for %s: %s", fqdn, exc)
            if addresses:
                resolved_count += 1
                logger.debug("Resolve success %s -> %s", fqdn, ", ".join(addresses))
            else:
                failed_count += 1
                logger.debug("Resolve failed %s: %s", fqdn, error or "no answer")
            results[fqdn] = {"addresses": addresses, "error": error}
            if processed_count % RESOLVE_PROGRESS_INTERVAL == 0:
                logger.info(
                    "Resolve progress: %d/%d resolved=%d failed=%d",
                    processed_count,
                    total,
                    resolved_count,
                    failed_count,
                )
    logger.info(
        "Resolve complete: %d/%d resolved=%d failed=%d",
        total,
        total,
        resolved_count,
        failed_count,
    )
    return results


def print_fqdns(filtered, resolve, resolutions=None):
    """
    Print FQDN output to stdout, resolving names when requested.
    """
    if resolve == "yes":
        logger.info("Resolve FQDNs: yes")
        if resolutions is None:
            resolutions = resolve_fqdns(filtered, workers=25)
        for fqdn in filtered:
            data = resolutions.get(fqdn, {"addresses": [], "error": "no result"})
            if data["addresses"]:
                print(f"{fqdn} -> {', '.join(data['addresses'])}")
            else:
                reason = data.get("error") or "no answer"
                print(f"{fqdn} -> ERROR: {reason}")
        return

    for fqdn in filtered:
        print(fqdn)


def chunk_items(items, chunk_size=CHUNK_SIZE):
    """
    Yield items in fixed-size chunks.
    """
    for start in range(0, len(items), chunk_size):
        yield items[start : start + chunk_size]


def learn_fqdns(config, filtered, resolutions=None):
    """
    Import resolved FQDNs matching configured regexes into Plum targets.
    """
    regexes = compile_learn_regexes(config)
    if not regexes:
        logger.warning("Learn enabled but last_fqdns_learn has no valid regex")
        return

    candidates = [
        fqdn for fqdn in filtered if any(regex.search(fqdn) for regex in regexes)
    ]
    logger.info("Learn regex matched FQDN count: %d", len(candidates))
    if not filtered:
        return

    if resolutions is None:
        resolutions = resolve_fqdns(filtered, workers=25)

    if not candidates:
        return

    learned = [
        fqdn for fqdn in candidates if resolutions.get(fqdn, {}).get("addresses")
    ]
    logger.info("Learn resolved FQDN count: %d", len(learned))
    if not learned:
        return

    base_url, username, password = load_plum_config(config)
    token = get_access_token(base_url, username, password)

    for chunk_index, chunk in enumerate(chunk_items(learned), start=1):
        result = bulk_import_targets(base_url, token, "\n".join(chunk))
        logger.info(
            "Learn import chunk %d submitted FQDN count: %d",
            chunk_index,
            len(chunk),
        )
        logger.debug("Learn import chunk %d result: %s", chunk_index, result)


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

    def is_ipv4(label):
        try:
            return isinstance(ipaddress.ip_address(label), ipaddress.IPv4Address)
        except ValueError:
            return False

    filtered = sorted(fqdn for fqdn in unique_fqdns if fqdn and not is_ipv4(fqdn))
    logger.info("Unique FQDN count: %d", len(filtered))

    resolutions = None
    if args.learn:
        resolutions = resolve_fqdns(filtered, workers=25)
        learn_fqdns(config, filtered, resolutions=resolutions)

    print_fqdns(filtered, args.resolve, resolutions=resolutions)


if __name__ == "__main__":
    main()
