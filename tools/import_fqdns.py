#!/bin/env python
"""
This script will retrieve read a file and inject all entries into Plum-Island
It accept FQDNS and IP's and CIDR


"""

import argparse
import json
import sys
from pathlib import Path

from lib.config import load_yaml_config, plum_credentials_from_config
from lib.dns import is_ip_or_cidr, resolve_fqdn
from lib.iterables import chunk_items
from lib.plum_api import bulk_import_targets, get_access_token
from lib.tool_logging import get_logger, setup_logger as setup_tool_logger

CONFIG_PATH = Path(__file__).with_name("config.yaml")
LOG_DIR = Path(__file__).with_name("log")
CHUNK_SIZE = 150  # How many lines to import at once with the API

logger = get_logger()


def setup_logger(debug=False):
    """
    Configure Rich console logging and the persistent daily-rotated log file.
    """
    return setup_tool_logger(LOG_DIR / "import_fqdns.log", debug=debug, logger=logger)


def load_plum_config() -> tuple[str, str, str]:
    """
    Load API base URL and credentials from config.yaml.
    """

    config = load_yaml_config(CONFIG_PATH)
    return plum_credentials_from_config(config, CONFIG_PATH)


def parse_args() -> argparse.Namespace:
    """
    Build the CLI parser for this script.
    """

    parser = argparse.ArgumentParser(
        description="Bulk-import FQDNs/IPs/CIDRs into Plum-Island.",
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-f",
        "--file",
        dest="input_file",
        help="Path to the newline-delimited targets file.",
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read newline-delimited targets from standard input.",
    )
    parser.add_argument(
        "--fqdn-resolving",
        action="store_true",
        help="Only import FQDN entries that resolve to at least one IP address.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show debug logs on console, including each FQDN resolution",
    )
    return parser.parse_args()


def load_targets_file(file_path: str | Path) -> list[str]:
    """
    Read a file containing one target per line and return cleaned entries.
    """

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Targets file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        entries = load_targets_lines(handle)

    if not entries:
        raise ValueError(f"No targets found in {path}")

    return entries


def load_targets_stdin() -> list[str]:
    """
    Read targets from standard input and return cleaned entries.
    """

    entries = load_targets_lines(sys.stdin)
    if not entries:
        raise ValueError("No targets found on stdin")

    return entries


def load_targets_lines(lines) -> list[str]:
    """
    Return non-empty stripped target lines.
    """

    entries: list[str] = []
    for raw_line in lines:
        entry = raw_line.strip()
        if entry:
            entries.append(entry)
    return entries


def chunk_targets(entries: list[str], chunk_size: int = CHUNK_SIZE):
    """
    Yield the targets list in chunks of at most `chunk_size`.
    """

    yield from chunk_items(entries, chunk_size)


def filter_targets_by_fqdn_resolution(entries: list[str]) -> list[str]:
    """
    Keep IP/CIDR entries and only keep FQDNs that resolve to an IP.
    """

    filtered = []
    skipped = 0

    logger.info("Resolve FQDN filter input count: %d", len(entries))
    for entry in entries:
        if is_ip_or_cidr(entry):
            logger.debug("Keep IP/CIDR target: %s", entry)
            filtered.append(entry)
            continue

        addresses = resolve_fqdn(entry)
        if addresses:
            logger.debug("Resolve success %s -> %s", entry, ", ".join(addresses))
            filtered.append(entry)
        else:
            skipped += 1
            logger.debug("Resolve failed %s: no answer", entry)

    logger.info(
        "FQDN resolving filter: %d kept, %d unresolved FQDN skipped",
        len(filtered),
        skipped,
    )
    return filtered


if __name__ == "__main__":
    args = parse_args()
    setup_logger(debug=args.debug)
    base_url, username, password = load_plum_config()
    targets = load_targets_stdin() if args.stdin else load_targets_file(args.input_file)
    logger.info("Targets loaded: %d", len(targets))
    if args.fqdn_resolving:
        targets = filter_targets_by_fqdn_resolution(targets)
        if not targets:
            logger.info("No targets to import after FQDN resolving filter")
            raise SystemExit(0)

    token = get_access_token(base_url, username, password)

    for chunk_index, chunk in enumerate(chunk_targets(targets), start=1):
        bulk_payload = "\n".join(chunk)
        result = bulk_import_targets(base_url, token, bulk_payload)
        logger.info("Chunk %d (%d entries)", chunk_index, len(chunk))
        logger.debug("Chunk %d result: %s", chunk_index, json.dumps(result, indent=4))
