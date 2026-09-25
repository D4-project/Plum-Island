"""Bounded WHOIS lookups for network and registered-domain targets."""

import ipaddress
import re
import socket
import time

from .domains import parse_hostname

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
    """Raised when a WHOIS lookup cannot be completed safely."""


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


def _query_public_registry(server, query):
    """Resolve a registry referral once; connect only to a public resolved IP."""
    if not server.startswith("whois.") or parse_hostname(server) is None:
        raise WhoisLookupError("IANA returned an invalid WHOIS referral")
    try:
        addresses = socket.getaddrinfo(server, 43, type=socket.SOCK_STREAM)
    except OSError as error:
        raise WhoisLookupError("WHOIS registry DNS lookup failed") from error
    public_addresses = [
        address for address in addresses
        if ipaddress.ip_address(address[4][0]).is_global
    ]
    if not public_addresses:
        raise WhoisLookupError("WHOIS referral has no public address")
    family, kind, protocol, _, socket_address = public_addresses[0]
    deadline = time.monotonic() + WHOIS_TIMEOUT_SECONDS
    response = bytearray()
    try:
        with socket.socket(family, kind, protocol) as connection:
            connection.settimeout(WHOIS_TIMEOUT_SECONDS)
            connection.connect(socket_address)
            connection.sendall(query.encode("ascii") + b"\r\n")
            while len(response) <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WhoisLookupError("WHOIS server timed out")
                connection.settimeout(remaining)
                chunk = connection.recv(min(65536, MAX_RESPONSE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
    except (OSError, UnicodeError) as error:
        raise WhoisLookupError("WHOIS server is unavailable") from error
    if len(response) > MAX_RESPONSE_BYTES:
        raise WhoisLookupError("WHOIS response exceeded the size limit")
    return response.decode("utf-8", errors="replace").strip()


def lookup_domain_whois(value):
    """Query IANA for a FQDN's registry, then WHOIS for its pyfaup domain."""
    parsed = parse_hostname(value)
    if parsed is None:
        raise WhoisLookupError("WHOIS requires a FQDN with a known public suffix")
    query = parsed["domain"]
    root_tld = parsed["tld"].rsplit(".", 1)[-1]
    iana_result = _query_server(IANA_WHOIS_SERVER, root_tld)
    referral = REFERRAL_PATTERN.search(iana_result)
    if referral is None:
        return query, iana_result
    result = _query_public_registry(referral.group(1).lower().rstrip("."), query)
    if not result:
        raise WhoisLookupError("WHOIS registry returned an empty response")
    return query, result
