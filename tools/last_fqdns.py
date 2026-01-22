#!/bin/env python
"""
Extract from the kvrocks DB the latest FQDNS
This tool may resolve directly for PDNS accounting.
"""

import argparse
import concurrent.futures
import ipaddress
import socket
import sys
from datetime import datetime, timedelta, timezone

import yaml

sys.path.append("../webapp/app/utils")  # parent of webapp
from kvrocks import KVrocksIndexer  # noqa: E402

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

KVROCKS_PORT = config.get("OUT_KVROCKS_PORT")
KVROCKS_HOST = config.get("OUT_KVROCKS_HOST")


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
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(resolve_single_fqdn, fqdn): fqdn for fqdn in fqdns
        }
        for future in concurrent.futures.as_completed(future_map):
            fqdn = future_map[future]
            try:
                addresses, error = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                addresses, error = [], str(exc)
            results[fqdn] = {"addresses": addresses, "error": error}
    return results


def main():
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
    args = parser.parse_args()

    if args.hours <= 0:
        parser.error("--hours must be a positive integer")

    cutoff_ts = int(
        (datetime.now(tz=timezone.utc) - timedelta(hours=args.hours)).timestamp()
    )

    indexer = KVrocksIndexer(KVROCKS_HOST, KVROCKS_PORT)
    redis_client = indexer.r

    uid_list = redis_client.zrevrangebyscore("last_seen_index", "+inf", cutoff_ts)
    unique_fqdns = set()
    for uid in uid_list:
        unique_fqdns.update(redis_client.smembers(f"fqdns:{uid}"))

    def is_ipv4(label):
        try:
            return isinstance(ipaddress.ip_address(label), ipaddress.IPv4Address)
        except ValueError:
            return False

    filtered = sorted(fqdn for fqdn in unique_fqdns if fqdn and not is_ipv4(fqdn))

    if args.resolve == "yes":
        resolutions = resolve_fqdns(filtered, workers=25)
        for fqdn in filtered:
            data = resolutions.get(fqdn, {"addresses": [], "error": "no result"})
            if data["addresses"]:
                print(f"{fqdn} -> {', '.join(data['addresses'])}")
            else:
                reason = data.get("error") or "no answer"
                print(f"{fqdn} -> ERROR: {reason}")
    else:
        for fqdn in filtered:
            print(fqdn)


if __name__ == "__main__":
    main()
