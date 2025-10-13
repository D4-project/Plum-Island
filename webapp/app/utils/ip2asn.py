"""
This module will resolve:
    IP to AS
    AS to Description

It use CIRCL Backend for resolution.
"""

import pybgpranking2
import pyipasnhistory

from netaddr import IPNetwork


def get_asn_description_for_ip(net_or_ip: str) -> str:
    """
    Complete workflow: fetch ASN for the given IP/CIDR and return its description
    for today’s date in UTC. Returns "Backend unreachable" on network or HTTP errors.
    """
    range_obj = IPNetwork(net_or_ip)

    ip2as = pyipasnhistory.IPASNHistory()
    data = ip2as.query(str(range_obj[0]))
    if not data or "response" not in data or not data["response"]:
        return "resolutions backend unreachable"

    date_key = next(iter(data["response"]))
    bgpas = data["response"][date_key].get("asn")

    as2str = pybgpranking2.PyBGPRanking()
    data = as2str.query(bgpas)
    if not data or "response" not in data or not data["response"]:
        return "resolutions backend unreachable"

    bgpinfo = data["response"].get("asn_description")

    return f"{bgpas}, {bgpinfo}"
