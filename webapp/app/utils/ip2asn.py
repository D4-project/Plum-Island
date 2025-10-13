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
    data1 = data

    # IP Asn History may give a result like that...
    # We need to iterate on date to find the smalest one out of providers.
    #'response': {'2025-10-13T00:00:00': {'asn': '53471', 'prefix': '192.0.0.0/3', 'source': 'ripe_rrc00'},
    #             '2025-10-11T12:00:00': {'asn': '6661', 'prefix': '194.154.192.0/19', 'source': 'caida'}}}
    smalest = ""
    smalest_len = 2**128  # 340282366920938463463374607431768211456 Max IPV6 network
    for date_key in iter(data["response"]):
        bgpas_net = IPNetwork(data["response"][date_key].get("prefix"))
        if len(bgpas_net) < smalest_len:
            smalest_len = len(bgpas_net)
            smalest = data["response"][date_key].get("asn")

    bgpas = smalest

    as2str = pybgpranking2.PyBGPRanking()
    data = as2str.query(smalest)
    if not data or "response" not in data or not data["response"]:
        return "resolutions backend unreachable"

    bgpinfo = data["response"].get("asn_description")

    return f"{bgpas}, {bgpinfo}"  #  {str(data)} -- {str(data1)}"
