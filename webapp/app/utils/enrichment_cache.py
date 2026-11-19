"""Shared WHOIS, Passive DNS and IP/AS source responses for UI and reports."""

import hashlib
import hmac
import ipaddress
import json
import time

import requests

from .ip_whois import (
    lookup_network_whois,
    WhoisLookupError,
    WHOIS_TIMEOUT_SECONDS,
    RIR_WHOIS_SERVERS,
)
from .lookup_cache import cached_response, configuration, LookupBusy
from .circl_lookup import fetch_network_payload

PDNS_TIMEOUT = 15
PDNS_MAX_BYTES = 8 * 1024 * 1024


def network_whois(value, config=None):
    """Cache exact canonical networks; do not infer ownership of other hosts."""
    query = ipaddress.ip_network(value, strict=False).with_prefixlen

    def load():
        result = lookup_network_whois(query)
        if not result.strip():
            raise WhoisLookupError("WHOIS registry returned an empty response")
        return result

    try:
        return cached_response(
            "whois:" + query,
            "WHOIS_CACHE_HOURS",
            24,
            load,
            WHOIS_TIMEOUT_SECONDS * (2 + 2 * len(RIR_WHOIS_SERVERS)),
            config,
            validator=lambda value: isinstance(value, str) and bool(value.strip()),
        )
    except LookupBusy as error:
        raise WhoisLookupError(str(error)) from error


def _credential_scope(config, username, password):
    """Keyed fingerprint: isolate credentials without putting secrets in keys."""
    secret = config.get("SECRET_KEY")
    if not secret:
        return None
    secret = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    material = "".join(
        json.dumps(value or "", ensure_ascii=True) + "|"
        for value in (username, password)
    )
    return hmac.new(secret, material.encode("utf-8"), hashlib.sha3_512).hexdigest()


def _pdns_source(address, username, password):
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
        records = [
            json.loads(line)
            for line in payload.decode("utf-8").splitlines()
            if line.strip()
        ]
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("Expected Passive DNS records")
        return records
    except (requests.RequestException, ValueError, UnicodeError) as error:
        raise LookupError(
            "Passive DNS lookup failed, timed out or returned an invalid response"
        ) from error


def passive_dns(value, username, password, config=None):
    """Cache raw observations before report filtering or resolve-token signing."""
    address = str(ipaddress.ip_address(value))
    if not username or not password:
        raise LookupError("Passive DNS credentials are not configured")
    config = configuration(config)
    scope = _credential_scope(config, username, password)
    # Without a deployment secret there is no safe shared credential namespace.
    cache_config = config if scope else {}
    return cached_response(
        f"pdns:{scope}:{address}",
        "PDNS_CACHE_HOURS",
        12,
        lambda: _pdns_source(address, username, password),
        PDNS_TIMEOUT * 2,
        cache_config,
        validator=lambda value: isinstance(value, list)
        and all(isinstance(item, dict) for item in value),
    )


def ip_information(value, timeout=10, config=None, force=False):
    """One response contains both IP geolocation and AS data."""
    address = str(ipaddress.ip_network(value, strict=False).network_address)

    def load():
        payload = fetch_network_payload(address, timeout)
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise ValueError("Expected CIRCL result array")
        if not payload:
            raise ValueError("Empty CIRCL response")
        return payload

    return cached_response(
        "ip-info:" + address,
        "IP_INFO_CACHE_HOURS",
        24,
        load,
        timeout * 3,
        config,
        force=force,
        validator=lambda value: isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) for item in value),
    )
