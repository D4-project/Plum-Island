"""Bounded DNS enrichment and spreadsheet-safe CSV for matching IP exports."""

import csv
from datetime import datetime, timezone
import ipaddress
import json
import math
import time

import requests

from .pdns_resolve import normalize_hostname
from .reports import collect_report_ptr_fqdns

PDNS_TIMEOUT = 15.0
PDNS_MAX_BYTES = 8 * 1024 * 1024
CSV_HEADER = ("ip", "last seen", "ptr", "pdns")


def csv_cell(value):
    """Neutralize formula prefixes; csv.writer handles delimiters and quotes."""
    text = str(value or "")
    if text.startswith(
        ("=", "+", "-", "@", "\t", "\r", "\n")
    ) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def last_seen_text(value):
    """Format indexed epoch seconds in UTC; missing values stay empty."""
    if value is None:
        return ""
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (ValueError, TypeError, OverflowError, OSError):
        return ""


def pdns_hostname(record, address):
    """Accept forward/inverse A or AAAA records only for the exported IP."""
    if not isinstance(record, dict):
        return None
    kind = "A" if address.version == 4 else "AAAA"
    if str(record.get("rrtype", "")).upper() != kind:
        return None
    for host_key, ip_key in (("rrname", "rdata"), ("rdata", "rrname")):
        try:
            record_ip = ipaddress.ip_address(record.get(ip_key))
        except (ValueError, TypeError):
            continue
        if record_ip == address:
            return normalize_hostname(record.get(host_key))
    return None


def pdns_in_time_range(record, time_range):
    """Require a valid observation interval overlapping the search, inclusively."""
    if not isinstance(record, dict):
        return False
    values = (record.get("time_first"), record.get("time_last"))
    if any(isinstance(value, bool) for value in values):
        return False
    try:
        first, last = (float(value) for value in values)
    except (ValueError, TypeError, OverflowError):
        return False
    return (
        math.isfinite(first)
        and math.isfinite(last)
        and 0 < first <= last
        and first <= time_range["to_ts"]
        and last >= time_range["from_ts"]
    )


def lookup_pdns(ip, username, password, time_range):
    """Read existing CIRCL records only; never follow redirects or active queries."""
    address = ipaddress.ip_address(ip)
    deadline = time.monotonic() + PDNS_TIMEOUT
    try:
        with requests.get(
            f"https://www.circl.lu/pdns/query/{address}",
            auth=(username, password),
            headers={"dribble-disable-active-query": "1"},
            timeout=(5, PDNS_TIMEOUT),
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise LookupError("Passive DNS lookup failed")
            payload = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if (
                    time.monotonic() > deadline
                    or len(payload) + len(chunk) > PDNS_MAX_BYTES
                ):
                    raise LookupError(
                        "Passive DNS response exceeded time or size limit"
                    )
                payload.extend(chunk)
    except requests.RequestException as error:
        raise LookupError("Passive DNS lookup failed or timed out") from error
    names = set()
    try:
        for line in payload.decode("utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if not pdns_in_time_range(record, time_range):
                    continue
                name = pdns_hostname(record, address)
                if name:
                    names.add(name)
    except (ValueError, UnicodeError) as error:
        raise LookupError("Passive DNS returned an invalid response") from error
    return sorted(names)


def write_resolved_csv(output, results, config, progress, warning, *, document_loader):
    """One row per matching IP, not per UID; failed lookups never drop an IP."""
    # Explicit I/O callbacks keep storage, progress and warnings independently testable.
    # pylint: disable=too-many-arguments
    writer = csv.writer(output)
    writer.writerow(CSV_HEADER)
    username = str(config.get("PASSIVE_USER") or "").strip()
    password = str(config.get("PASSIVE_PWD") or "")
    if not username or not password:
        warning(
            "Passive DNS unavailable: configure PASSIVE_USER and PASSIVE_PWD; PDNS cells are empty."
        )
    ips = sorted(
        results["results"],
        key=lambda ip: (
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )
    for done, ip in enumerate(ips, 1):
        names = []
        ptrs = collect_report_ptr_fqdns(document_loader, {ip: results["results"][ip]})[
            ip
        ]
        if username and password:
            try:
                names = lookup_pdns(ip, username, password, results["time_range"])
            except LookupError as error:
                warning(f"{ip}: {error}")
        writer.writerow(
            [
                csv_cell(value)
                for value in (
                    ip,
                    last_seen_text(
                        results.get("timestamps", {}).get(ip, {}).get("max_seen")
                    ),
                    ",".join(ptrs),
                    ",".join(names),
                )
            ]
        )
        progress(done)
