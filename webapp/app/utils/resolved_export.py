"""Bounded DNS enrichment and spreadsheet-safe CSV for matching IP exports."""

import csv
from datetime import datetime, timezone
import ipaddress
import json
import time

import dns.exception
import dns.resolver
import dns.reversename
import requests

from .pdns_resolve import normalize_hostname

DNS_TIMEOUT = 5.0
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


def lookup_ptr(ip):
    """Use the configured DNS resolver, absolute reverse name, finite lifetime."""
    address = str(ipaddress.ip_address(ip))
    try:
        answer = dns.resolver.Resolver().resolve(
            dns.reversename.from_address(address),
            "PTR",
            lifetime=DNS_TIMEOUT,
            search=False,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError) as error:
        raise LookupError("PTR lookup failed or timed out") from error
    return sorted(
        {name for item in answer if (name := normalize_hostname(item.target.to_text()))}
    )


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


def lookup_pdns(ip, username, password):
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
                name = pdns_hostname(json.loads(line), address)
                if name:
                    names.add(name)
    except (ValueError, UnicodeError) as error:
        raise LookupError("Passive DNS returned an invalid response") from error
    return sorted(names)


def write_resolved_csv(output, results, config, progress, warning):
    """One row per matching IP, not per UID; failed lookups never drop an IP."""
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
        ptrs = []
        try:
            ptrs = lookup_ptr(ip)
        except LookupError as error:
            warning(f"{ip}: {error}")
        if username and password:
            try:
                names = lookup_pdns(ip, username, password)
            except LookupError as error:
                warning(f"{ip}: {error}")
        last_seen = results.get("timestamps", {}).get(ip, {}).get("max_seen")
        writer.writerow(
            [
                csv_cell(value)
                for value in (
                    ip,
                    last_seen_text(last_seen),
                    ",".join(ptrs),
                    ",".join(names),
                )
            ]
        )
        progress(done)
