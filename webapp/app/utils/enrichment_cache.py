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


class PassiveDNSError(LookupError):
    """Safe Passive DNS failure with a stable UI error code."""

    code = "upstream"


class PassiveDNSDisabled(PassiveDNSError):
    """The operator has disabled Passive DNS."""

    code = "disabled"


class PassiveDNSAuthenticationError(PassiveDNSError):
    """CIRCL rejected the configured credentials."""

    code = "authentication"


class PassiveDNSTimeout(PassiveDNSError):
    """CIRCL did not finish the request within the timeout."""

    code = "timeout"


class PassiveDNSInvalidResponse(PassiveDNSError):
    """CIRCL returned data that cannot be used safely."""

    code = "invalid_response"


def passive_dns_enabled(config, username, password):
    """Preserve legacy credential-based activation when no flag exists."""
    if "PDNS_ENABLED" in config:
        return config["PDNS_ENABLED"] is True
    return bool(str(username or "").strip() and str(password or ""))


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
            if response.status_code in (401, 403):
                raise PassiveDNSAuthenticationError(
                    "Passive DNS credentials were rejected"
                )
            if response.status_code != 200:
                raise PassiveDNSError("Passive DNS service returned an error")
            payload = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if time.monotonic() > deadline:
                    raise PassiveDNSTimeout("Passive DNS lookup timed out")
                if len(payload) + len(chunk) > PDNS_MAX_BYTES:
                    raise PassiveDNSInvalidResponse(
                        "Passive DNS response exceeded its size limit"
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
    except requests.Timeout as error:
        raise PassiveDNSTimeout("Passive DNS lookup timed out") from error
    except requests.RequestException as error:
        raise PassiveDNSError("Passive DNS service is unavailable") from error
    except (ValueError, UnicodeError) as error:
        raise PassiveDNSInvalidResponse(
            "Passive DNS returned an invalid response"
        ) from error


def passive_dns(value, username, password, config=None):
    """Cache raw observations before report filtering or resolve-token signing."""
    config = configuration(config)
    if not passive_dns_enabled(config, username, password):
        raise PassiveDNSDisabled("Passive DNS disabled")
    address = str(ipaddress.ip_address(value))
    if not username or not password:
        raise PassiveDNSAuthenticationError(
            "Passive DNS credentials are not configured"
        )
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
