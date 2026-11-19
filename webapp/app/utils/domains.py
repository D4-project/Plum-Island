"""Domain validation and extraction through pyfaup's public-suffix data."""

import ipaddress

import idna
from pyfaup import FaupCompat  # pylint: disable=no-name-in-module


def is_hostname_syntax(value):
    """Accept a DNS hostname even when its suffix is absent from pyfaup."""
    hostname = str(value or "").strip().rstrip(".")
    if "." not in hostname:
        return False
    try:
        ascii_name = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return False
    labels = ascii_name.split(".")
    return (
        len(ascii_name) <= 253
        and all(0 < len(label) <= 63 for label in labels)
        and len(labels[-1]) >= 2
        and labels[-1][0].isalpha()
    )


def parse_hostname(value, extra_suffixes=()):
    """Return normalized FQDN parts, or None for invalid/unknown domains."""
    hostname = str(value or "").strip().rstrip(".")
    if not hostname or "." not in hostname:
        return None
    try:
        hostname = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii").lower()
        if len(hostname) > 253:
            return None
    except (idna.IDNAError, UnicodeError):
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    try:
        parser = FaupCompat()
        parser.decode(f"http://{hostname}")
        parsed = parser.get()
        suffix = parsed.get("tld")
        if not suffix or str(parsed.get("host")) != hostname:
            return None
        suffix_text = str(suffix).lower()
        allowed = {str(item).strip().lower().lstrip(".") for item in extra_suffixes or ()}
        if not suffix.is_known() and suffix_text not in allowed:
            return None
        domain = parsed.get("domain")
        if not domain:
            return None
        return {
            "fqdn": hostname,
            "host": str(parsed.get("subdomain") or "").lower(),
            "domain": str(domain).lower(),
            "tld": suffix_text,
        }
    except (ValueError, TypeError, AttributeError):
        return None
