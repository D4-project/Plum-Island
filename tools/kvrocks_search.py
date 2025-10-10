#!/bin/env python
import sys
import redis
from datetime import datetime
from netaddr import IPNetwork, IPAddress

sys.path.append("../webapp/app/utils")  # parent of webapp
from kvrocks import KVrocksIndexer

indexer = KVrocksIndexer()

indexer.flushdb

docs = [
    {
        "uid": "uid1",
        "ip": "192.168.1.1",
        "favicon_hashes": ["f1", "fX"],
        "http_servers": ["apache 2.4"],
        "http_cookies": ["c1", "cA"],
        "ports": [80, 443],
    },
    {
        "uid": "uid2",
        "ip": "192.168.1.2",
        "favicon_hashes": ["f2"],
        "http_servers": ["nginx 1.18"],
        "http_cookies": ["c2"],
        "ports": [80, 443],
    },
    {
        "uid": "uid3",
        "ip": "192.168.1.3",
        "favicon_hashes": ["f3"],
        "http_servers": ["apache 2.2"],
        "http_cookies": [],
        "ports": [8080],
    },
    {
        "uid": "uid4",
        "ip": "192.168.1.3",
        "favicon_hashes": ["f3"],
        "http_servers": ["apache 2.5"],
        "http_cookies": [],
        "ports": [],
    },
    {
        "uid": "uid5",
        "ip": "192.168.1.3",
        "favicon_hashes": ["f3"],
        "http_servers": ["apache:2.5", "apache|toto"],
        "http_cookies": [],
        "ports": [],
    },
]

# indexer.add_documents_batch(docs)

print(".eq or missing means equals , faster ")
print(".lk or .like means like")
print(".bg or .begin mens start_with)")
print("Fields are:  net, ip, http_cookie, http_servers , port")
print()
criteria = {"http_server.begin": "apache", "http_cookie": "c1", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_server.bg": "apache", "http_cookie": "c1", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)


criteria = {"http_server.bg": "nginx", "http_cookie": "fX"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)


criteria = {"http_server.lk": "1.18", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"ip": "192.168.1.3"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

# criteria = {}
# $uids = indexer.get_uids_by_criteria(criteria)
# print("Matching UIDs:", criteria, uids)

criteria = {"http_server.begin": "1.18", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_server.begin": "apache"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)
criteria = {"http_server": "apache", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"port": "80", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"port.start": "80", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_title.bg": "Index of"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_server.begin": "apache"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_cookie.lk": "vpn"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_title": "Index of /"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"net": "147.67.0.0/16"}
uids = indexer.get_uids_by_criteria(criteria)
uidswithip = indexer.get_ip_from_uids(uids)
print("Matching UIDs:", criteria, uids)

criteria = {"http_server.bg": "apach"}
uids = indexer.get_uids_by_criteria(criteria)
uidswithip = indexer.get_ip_from_uids(uids)
print("Matching UIDs:", criteria, uids)
print("Matching IP:", uidswithip)
