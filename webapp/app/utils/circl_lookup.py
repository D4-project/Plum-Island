"""Standalone transport for the fixed CIRCL IP/AS endpoint."""

import ipaddress
import requests

CIRCL_LOOKUP_URL = "https://ip.circl.lu/geolookup/"


def fetch_network_payload(value, timeout=10):
    """Fetch one normalized network address without following redirects."""
    address = str(ipaddress.ip_network(value, strict=False).network_address)
    response = requests.get(
        CIRCL_LOOKUP_URL + address, timeout=timeout, allow_redirects=False
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise ValueError("Unexpected CIRCL response status")
    return response.json()
