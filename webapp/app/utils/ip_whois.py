"""Bounded WHOIS lookups for IPv4 and IPv6 network targets."""

import ipaddress
import re
import socket
import time

IANA_WHOIS_SERVER = "whois.iana.org"
RIR_WHOIS_SERVERS = frozenset(
    {
        "whois.afrinic.net",
        "whois.apnic.net",
        "whois.arin.net",
        "whois.lacnic.net",
        "whois.ripe.net",
    }
)
WHOIS_TIMEOUT_SECONDS = 6
MAX_RESPONSE_BYTES = 512 * 1024
REFERRAL_PATTERN = re.compile(
    r"^(?:refer|whois):\s*(?:whois://)?([a-z0-9.-]+)\s*$", re.IGNORECASE | re.MULTILINE
)


class WhoisLookupError(Exception):
    """Raised when an RIR lookup cannot be completed safely."""


def _query_server(server, query):
    """Read one bounded WHOIS response from a fixed/allowlisted host."""
    deadline = time.monotonic() + WHOIS_TIMEOUT_SECONDS
    response = bytearray()
    try:
        with socket.create_connection(
            (server, 43), timeout=WHOIS_TIMEOUT_SECONDS
        ) as connection:
            connection.sendall(query.encode("ascii") + b"\r\n")
            while len(response) <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WhoisLookupError("WHOIS server timed out")
                connection.settimeout(remaining)
                chunk = connection.recv(
                    min(65536, MAX_RESPONSE_BYTES + 1 - len(response))
                )
                if not chunk:
                    break
                response.extend(chunk)
    except (OSError, UnicodeError) as error:
        raise WhoisLookupError("WHOIS server is unavailable") from error
    if len(response) > MAX_RESPONSE_BYTES:
        raise WhoisLookupError("WHOIS response exceeded the size limit")
    return response.decode("utf-8", errors="replace").strip()


def lookup_network_whois(value):
    """Query IANA, follow one allowlisted RIR referral, return plain text."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (TypeError, ValueError) as error:
        raise WhoisLookupError("WHOIS is available only for IP/CIDR targets") from error

    query = network.with_prefixlen
    iana_result = _query_server(IANA_WHOIS_SERVER, query)
    referral = REFERRAL_PATTERN.search(iana_result)
    if referral is None:
        return iana_result

    server = referral.group(1).lower().rstrip(".")
    if server not in RIR_WHOIS_SERVERS:
        raise WhoisLookupError("IANA returned an unsupported WHOIS referral")
    rir_result = _query_server(server, query)
    if not rir_result:
        raise WhoisLookupError("WHOIS registry returned an empty response")
    return rir_result
