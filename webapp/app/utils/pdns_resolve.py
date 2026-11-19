"""Bounded, on-demand A lookups; never write passive observation history."""

import ipaddress
import re
from threading import BoundedSemaphore
import time

import dns.exception
import dns.resolver
import idna
from itsdangerous import BadData, URLSafeTimedSerializer

# Conservative per-process limits, not production-tuned throughput targets.
LOOKUP_SECONDS = 5.0
LOOKUP_SLOTS = BoundedSemaphore(4)
TOKEN_MAX_AGE = 3600
TOKEN_SALT = "ip-pdns-resolve-v1"


def normalize_hostname(value):
    """Accept a DNS hostname, not an IP, option, URL or resolver search suffix."""
    if not isinstance(value, str) or not value or len(value) > 254:
        return None
    try:
        name = idna.encode(value.removesuffix("."), uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None
    if len(name) > 253 or "." not in name:
        return None
    labels = name.split(".")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def record_hostname(record, ip):
    """Handle forward and inverse PDNS payloads only when tied to this IPv4."""
    if str(record.get("rrtype", "")).upper() != "A":
        return None
    try:
        address = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return None
    for host_field, ip_field in (("rrname", "rdata"), ("rdata", "rrname")):
        try:
            record_ip = ipaddress.IPv4Address(record.get(ip_field))
        except (ipaddress.AddressValueError, TypeError):
            continue
        if record_ip == address:
            return normalize_hostname(record.get(host_field))
    return None


def add_resolve_tokens(records, ip, secret):
    """Copy records and sign eligible names, without trusting client DNS inputs."""
    signer = URLSafeTimedSerializer(secret, salt=TOKEN_SALT)
    result = []
    for record in records:
        item = dict(record)
        # Never trust enrichment fields supplied by an upstream source.
        item.pop("resolve_hostname", None)
        item.pop("resolve_token", None)
        hostname = record_hostname(item, ip)
        if hostname:
            item["resolve_hostname"] = hostname
            item["resolve_token"] = signer.dumps({"ip": ip, "hostname": hostname})
        result.append(item)
    return result


def verify_resolve_token(token, ip, secret):
    """Reject expired, modified or cross-IP lookup authorizations."""
    if not isinstance(token, str) or len(token) > 2048:
        raise ValueError("Invalid resolution token; reload Passive DNS")
    try:
        payload = URLSafeTimedSerializer(secret, salt=TOKEN_SALT).loads(
            token, max_age=TOKEN_MAX_AGE
        )
    except BadData as error:
        raise ValueError(
            "Resolution token invalid or expired; reload Passive DNS"
        ) from error
    if not isinstance(payload, dict) or payload.get("ip") != ip:
        raise ValueError("Resolution token does not match this IP")
    hostname = normalize_hostname(payload.get("hostname"))
    if not hostname:
        raise ValueError("Invalid resolution hostname")
    return hostname


def resolve_a(hostname, ip):
    """Resolve all A answers, with finite lifetime and no unbounded waiting pool."""
    # A context manager would block; reject excess work instead of queuing it.
    if not LOOKUP_SLOTS.acquire(blocking=False):  # pylint: disable=consider-using-with
        return {"hostname": hostname, "status": "busy", "checked_at": None}
    try:
        try:
            resolver = dns.resolver.Resolver()
            answer = resolver.resolve(
                hostname + ".", "A", lifetime=LOOKUP_SECONDS, search=False
            )
            addresses = {str(ipaddress.IPv4Address(item.address)) for item in answer}
            status = "matched" if ip in addresses else "mismatch"
        except dns.resolver.NXDOMAIN:
            status = "nxdomain"
        except dns.resolver.NoAnswer:
            status = "no_answer"
        except dns.exception.Timeout:
            status = "timeout"
        except (dns.exception.DNSException, OSError, ValueError):
            status = "error"
        return {"hostname": hostname, "status": status, "checked_at": time.time()}
    finally:
        LOOKUP_SLOTS.release()
