#!/bin/env python
"""
This script will retrieve read a file and inject all entries into Plum-Island
It accept FQDNS and IP's and CIDR


"""
import argparse
import json
import time
from pathlib import Path

import requests
import yaml

CONFIG_PATH = Path(__file__).with_name("config.yaml")
CHUNK_SIZE = 150  # How many lines to import at once with the API
MAX_RETRIES = 2  # SQL lite need to be removed one day.
RETRY_DELAY_SECONDS = 3


def load_plum_config() -> tuple[str, str, str]:
    """
    Load API base URL and credentials from config.yaml.
    """

    with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    try:
        base_url = config["PLUMISLAND"]
        username = config["PLUMAPIUSER"]
        password = config["PLUMAPIPWD"]
    except KeyError as exc:
        missing = exc.args[0]
        raise KeyError(f"Missing '{missing}' in {CONFIG_PATH}") from exc

    return base_url, username, password


def get_access_token(base_url: str, username: str, password: str) -> str:
    """
    Authenticate against Flask AppBuilder API and return access token.
    """

    login_url = f"{base_url}/api/v1/security/login"
    login_payload = {"username": username, "password": password, "provider": "db"}

    login_response = requests.post(login_url, json=login_payload, timeout=10)
    login_response.raise_for_status()

    login_data = login_response.json()
    access_token = login_data["access_token"]
    return access_token


def bulk_import_targets(base_url: str, access_token: str, bulk_payload: str) -> dict:
    """
    Call the bulk_import endpoint with the given access token and bulk payload.
    """

    bulk_import_url = f"{base_url}/targets_api/bulk_import"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {"bulk": bulk_payload}

    attempts = 0
    while True:
        try:
            response = requests.post(
                bulk_import_url,
                headers=headers,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as err:
            status_code = err.response.status_code if err.response is not None else None
            if status_code == 500 and attempts < MAX_RETRIES:
                attempts += 1
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise
        except (TimeoutError, requests.exceptions.ConnectionError) as err:
            if attempts < MAX_RETRIES:
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise


def parse_args() -> argparse.Namespace:
    """
    Build the CLI parser for this script.
    """

    parser = argparse.ArgumentParser(
        description="Bulk-import FQDNs/IPs/CIDRs into Plum-Island.",
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        dest="input_file",
        help="Path to the newline-delimited targets file.",
    )
    return parser.parse_args()


def load_targets_file(file_path: str | Path) -> list[str]:
    """
    Read a file containing one target per line and return cleaned entries.
    """

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Targets file not found: {path}")

    entries: list[str] = []

    # Read all lines, and Trim,
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            entry = raw_line.strip()
            if entry:
                entries.append(entry)

    if not entries:
        raise ValueError(f"No targets found in {path}")

    return entries


def chunk_targets(entries: list[str], chunk_size: int = CHUNK_SIZE):
    """
    Yield the targets list in chunks of at most `chunk_size`.
    """

    for start in range(0, len(entries), chunk_size):
        yield entries[start : start + chunk_size]


if __name__ == "__main__":
    args = parse_args()
    base_url, username, password = load_plum_config()
    targets = load_targets_file(args.input_file)

    token = get_access_token(base_url, username, password)

    for chunk_index, chunk in enumerate(chunk_targets(targets), start=1):
        bulk_payload = "\n".join(chunk)
        result = bulk_import_targets(base_url, token, bulk_payload)
        print(f"Chunk {chunk_index} ({len(chunk)} entries)")
        print(json.dumps(result, indent=4))
