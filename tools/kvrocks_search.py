#!/bin/env python
import sys
from datetime import datetime, timedelta, timezone

sys.path.append("../webapp/app/utils")  # parent of webapp
from kvrocks import KVrocksIndexer

indexer = KVrocksIndexer()

# indexer.flushdb()

now_ts = int(datetime.now(timezone.utc).timestamp())
old_ts = int((datetime.now(timezone.utc) - timedelta(days=120)).timestamp())

docs = [
    {
        "uid": "uid1",
        "ip": "192.168.1.1",
        "http_favicon_mmhash": ["f1", "fX"],
        "http_server": ["apache 2.4"],
        "http_cookiename": ["c1", "cA"],
        "port": [80, 443],
        "first_seen": old_ts,
        "last_seen": now_ts,
    },
    {
        "uid": "uid2",
        "ip": "192.168.1.2",
        "http_favicon_mmhash": ["f2"],
        "http_server": ["nginx 1.18"],
        "http_cookiename": ["c2"],
        "port": [80, 443],
        "first_seen": old_ts,
        "last_seen": now_ts,
    },
    {
        "uid": "uid3",
        "ip": "192.168.1.3",
        "http_favicon_mmhash": ["f3"],
        "http_server": ["apache 2.2"],
        "http_cookiename": [],
        "port": [8080],
        "first_seen": old_ts,
        "last_seen": now_ts,
    },
    {
        "uid": "uid4",
        "ip": "192.168.1.3",
        "http_favicon_mmhash": ["f3"],
        "http_server": ["apache 2.5"],
        "http_cookiename": [],
        "port": [],
        "first_seen": old_ts,
        "last_seen": now_ts,
    },
    {
        "uid": "uid5",
        "ip": "192.168.1.3",
        "http_favicon_mmhash": ["f3"],
        "http_server": ["apache:2.5", "apache|toto"],
        "http_cookiename": [],
        "port": [],
        "first_seen": old_ts,
        "last_seen": now_ts,
    },
]

# indexer.add_documents_batch(docs)

print(".eq or missing means equals , faster ")
print(".lk or .like means like")
print(".bg or .begin mens start_with)")
print("Fields are:  net, ip, http_cookiename, http_server, port")
print()
criteria = {"http_server.begin": "apache", "http_cookiename": "c1", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)

criteria = {"http_server.bg": "apache", "http_cookiename": "c1", "net": "192.168.1.0/24"}
uids = indexer.get_uids_by_criteria(criteria)
print("Matching UIDs:", criteria, uids)


criteria = {"http_server.bg": "nginx", "http_cookiename": "fX"}
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

criteria = {"http_cookiename.lk": "vpn"}
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

from_ts = int((datetime.now(timezone.utc) - timedelta(days=90)).timestamp())
to_ts = int(datetime.now(timezone.utc).timestamp())
uids = indexer.get_uids_by_time_range(from_ts, to_ts)
print("Matching UIDs in time range:", from_ts, to_ts, uids)
