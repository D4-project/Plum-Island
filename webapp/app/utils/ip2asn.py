"""Structured CIRCL network lookups, independent of Flask and database state."""

import ipaddress
import math
import requests

try:
    from .circl_lookup import fetch_network_payload
except ImportError:
    from circl_lookup import fetch_network_payload

INVALID_NETWORK_MESSAGE = "Network info unavailable for non-IP targets"


def target_type(value):
    """Classify hosts as /32 or /128 networks, without resolving FQDNs."""
    try:
        return f"IPv{ipaddress.ip_network(value, strict=False).version} CIDR"
    except (TypeError, ValueError):
        return "FQDN"


def network_address(value):
    """Return exactly the first address, including the IPv4 network address."""
    return str(ipaddress.ip_network(value, strict=False).network_address)


def _coordinate(value, bound):
    """Accept optional finite country-average coordinates."""
    if value in (None, ""):
        return None
    number = float(value)
    if not math.isfinite(number) or abs(number) > bound:
        raise ValueError("Invalid country coordinates")
    return number


def parse_network_information(payload):
    """Select the ASN-bearing entry, not the country-only first result."""
    if not isinstance(payload, list):
        raise ValueError("Expected CIRCL result array")
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        country = entry.get("country") or {}
        if not isinstance(country, dict):
            continue
        asn_value = country.get("AutonomousSystemNumber")
        if asn_value in (None, ""):
            continue
        raw_asn = str(asn_value)
        name = country.get("AutonomousSystemOrganization")
        if (
            not raw_asn.isascii()
            or not raw_asn.isdecimal()
            or not 0 <= int(raw_asn) <= 4294967295
        ):
            raise ValueError("Invalid ASN")
        if not isinstance(name, str) or not name.strip() or len(name) > 512:
            raise ValueError("Missing or invalid AS name")
        info = entry.get("country_info") or {}
        if not isinstance(info, dict):
            raise ValueError("Invalid country information")
        alpha3 = info.get("Alpha-3 code") or None
        numeric = info.get("Numeric code")
        numeric = str(numeric).zfill(3) if numeric not in (None, "") else None
        alpha2 = country.get("iso_code") or None
        # CIRCL uses the literal string "None" when no country is known.
        if alpha2 == "None":
            alpha2 = None
        if alpha3 is not None and (
            not isinstance(alpha3, str)
            or len(alpha3) != 3
            or not alpha3.isascii()
            or not alpha3.isalpha()
        ):
            raise ValueError("Invalid alpha-3 country code")
        if numeric is not None and (
            len(numeric) != 3 or not numeric.isascii() or not numeric.isdecimal()
        ):
            raise ValueError("Invalid numeric country code")
        if alpha2 is not None and (
            not isinstance(alpha2, str)
            or len(alpha2) != 2
            or not alpha2.isascii()
            or not alpha2.isalpha()
        ):
            raise ValueError("Invalid alpha-2 country code")
        return {
            "asn": int(raw_asn),
            "name": name.strip(),
            "country_alpha2": alpha2.upper() if alpha2 else None,
            "country_alpha3": alpha3.upper() if alpha3 else None,
            "country_numeric": numeric,
            "latitude": _coordinate(info.get("Latitude (average)"), 90),
            "longitude": _coordinate(info.get("Longitude (average)"), 180),
        }
    raise ValueError("No ASN information in CIRCL response")


class NetworkInformation(dict):
    """Structured AS values with the original source timestamp attached."""

    fetched_at = None


def lookup_network_information(value, timeout=10, force=False):
    """Reuse the same source response as the IP detail page."""
    if not __package__:
        return parse_network_information(fetch_network_payload(value, timeout))
    # pylint: disable=import-outside-toplevel
    from .enrichment_cache import (
        ip_information,
    )  # pylint: disable=import-outside-toplevel

    cached = ip_information(value, timeout=timeout, force=force)
    info = NetworkInformation(parse_network_information(cached["value"]))
    info.fetched_at = cached["fetched_at"]
    return info


def get_asn_description_for_ip(net_or_ip):
    """Compatibility wrapper for existing standalone diagnostic callers."""
    if target_type(net_or_ip) == "FQDN":
        return INVALID_NETWORK_MESSAGE
    try:
        info = lookup_network_information(net_or_ip)
        return f"{info['asn']}, {info['name']}"
    except (requests.RequestException, ValueError):
        return "Network lookup failed"
