#!/bin/env python

"""
This is the main module for searching using kvrocks.
It contains all the logic to find something.
"""

import datetime
import logging
import redis
from netaddr import IPNetwork

logger = logging.getLogger("flask_appbuilder")


class KVrocksIndexer:
    """
    Class for using Kvrock as search engine.w

    """

    def __init__(self, host="localhost", port=6666):
        self.r = redis.Redis(host=host, port=port, decode_responses=True, db=0)

    @staticmethod
    def now_rfc():
        """
        Return a timedate that kvrosk is happy with.
        """
        return datetime.utcnow().isoformat() + "Z"

    def flushdb(self):
        """
        This method will drop the index database
        """
        self.r.flushdb()

    def objects_count(self):
        """
        This methods returns the object count
        """
        all_counts = {
            "ip_count": self.r.scard("all_ips"),
            "uid_count": self.r.scard("all_uids"),
        }
        return all_counts

    def add_documents_batch(self, docs, batch_size=10000):
        """
        insert documents into the kvrocks.
        Each doc: dict with keys:
          uid, ip, favicon_hashes (list), http_servers (list), http_cookies (list)

        it does "batch insertions", up to 10K per insert by default
        """
        for i in range(0, len(docs), batch_size):
            batch = docs[i : i + batch_size]
            pipe = self.r.pipeline(transaction=False)
            for doc in batch:
                uid = doc["uid"]
                ip = doc["ip"]
                favicons = doc.get("http_favicon", [])
                http_servers = doc.get("http_servers", [])
                http_cookies = doc.get("http_cookies", [])
                http_titles = doc.get("http_titles", [])
                ports = doc.get("ports", [])
                last_seen = doc.get("last_seen")  # Document last time scanned.

                uid_key = f"doc:{uid}"
                existing = self.r.hgetall(uid_key)
                first_seen = doc.get("first_seen", last_seen)

                if existing:
                    # For the same UID ( meaning same scan result hsh256)
                    # we recompute last seen and first seen.
                    # We do like that because if case of insert bulk
                    first_seen = min(existing.get("first_seen", first_seen), first_seen)
                    last_seen = max(existing.get("last_seen", last_seen), last_seen)

                # Store hashset uid
                pipe.hset(
                    uid_key,
                    mapping={
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "ip": ip,
                    },
                )

                # Index IP
                pipe.sadd("all_ips", ip)  # Generic Spaces all IP
                pipe.sadd("all_uids", uid)  # Generic Space all UID's

                pipe.sadd(f"ip:{ip}", uid)  # Create a Set of many UID per IP
                pipe.set(
                    f"uid:{uid}", ip
                )  # Create a hash of One UID that give only one IP

                # Index network from 16 down to 24
                for mask in range(16, 25):
                    network = str(IPNetwork(f"{ip}/{mask}").network) + f"/{mask}"
                    pipe.sadd(f"net:{network}", uid)

                # Need to be "iterated magically" to avoid
                # Index favicons (multiple)
                for f in favicons:
                    pipe.sadd(
                        f"http_favicon:{f}", uid
                    )  # one favicon type gives many uid
                    pipe.sadd(f"http_favicons:{uid}", f)  # all object having favicons.

                # Index http_servers (multiple).. Could be refactored to "loop" a list instead.
                for s in http_servers:
                    pipe.sadd(
                        f"http_server:{s}", f"{uid}"
                    )  # idem.. one http_server set give all uid
                    pipe.sadd(f"http_servers:{uid}", s)  # idem....

                # Index http_cookies (multiple)
                for c in http_cookies:
                    pipe.sadd(f"http_cookie:{c}", f"{uid}")  # idem...
                    pipe.sadd(f"http_cookies:{uid}", c)

                # Index Ports (multiple)
                for p in ports:
                    pipe.sadd(f"port:{p}", f"{uid}")
                    pipe.sadd(f"ports:{uid}", p)

                # Index http_title (multiple)
                for p in http_titles:
                    pipe.sadd(f"http_title:{p}", f"{uid}")
                    pipe.sadd(f"http_titles:{uid}", p)

            pipe.execute()

    def get_uids_by_criteria(self, criteria: dict):
        """
        multi-criteria search:
        - Exact match: field:value
        - Prefix: field.bg or .begin:value
        - Substring: field.lk or .like:value
        - CIDR: net:<cidr>
        - Exact IP: ip:<value>

        Lookable is http_server, http_cookies, http_title, ip, net, port


        criteria example is
        {'http_title.like': ['ivanti', 'portal'], 'net': ['147.67.0.0/16'],
         'http_title.bg': ['ivanti'], 'http_cookie': ['JSESSIONID'], 'port': 80}


        The method used is the following.
        we get a first results, then and intersect with results of others keywords.

        1)   The inital results could be ip or cidr.
            This result is culumative, if 2 ip, or a ip or a cidr is given a "or" is done between them.
            to get the first results.

        2) If there are no ip or cidr, given.
            Then we look for the first exact match to get the inital list to intersect.

            2A) If there is no exact match.. then we get one query with modifier and we remove the modifier and do
            a scan_iter to get the initial results

        3 After that, for each remaining term, the results is intersected with the query...

        Need to be improved:
            DONOTSEARCH with port in 2B since every scan has obviously a PORT
            1 and 2 user with sscan
            Cache Results a couple of min ( hash query -> set + timeout).
        """

        remaining_criteria = dict(criteria)  # dict with all the key to seach.
        print(remaining_criteria)

        partial_result = None  # The Result space that will be intersected.

        # 1) We manage IP first
        if "ip" in remaining_criteria:
            ip_vals = remaining_criteria.pop("ip")
            if not isinstance(ip_vals, list):
                ip_vals = [ip_vals]

            uids_ip = set()
            for ip in ip_vals:
                uids_ip.update(
                    self.r.smembers(f"ip:{ip}")
                )  # Adding to the partial results all the Give IP's.
            partial_result = uids_ip
            # print("ip result")
            # print(partial_result)

        # 1) We manage the CIDRS
        if "net" in remaining_criteria:
            net_vals = remaining_criteria.pop("net")
            if not isinstance(net_vals, list):
                net_vals = [net_vals]

            uids_net = set()
            # For each net required, add corresponding uid it to uid_nets
            for net_val in net_vals:
                # Get uid of the given net
                uids_net.update(self.r.smembers(f"net:{net_val}"))

            if partial_result is None:
                partial_result = uids_net
            else:
                partial_result |= uids_net  # union with previous results

        # If the base seach is not there we create the basic set using one available exact match
        if partial_result is None:
            logger.debug("No IP/NET specified, get base UID")
            found_base = False
            for field, values in remaining_criteria.items():
                if not isinstance(values, list):
                    values = [values]
                for value in values:
                    base_field = field.split(".")[0]
                    suffix = field.split(".")[1] if "." in field else ""
                    if suffix == "":
                        logger.debug(
                            "Generate partial result by Looking at %s", base_field
                        )
                        uids = self.r.smembers(f"{base_field}:{value}")
                        if uids:
                            partial_result = set(uids)
                            remaining_criteria.pop(field)
                            found_base = True
                            break
                if found_base:
                    break

                # 2A) fallback: if no base, scan first criterion remove the .modifier and do not pop
            if partial_result is None:
                logger.debug("No plein search, looking by any modifier")

                # avoid using port as search ( as is retrieve everything.)
                # if only port.modifier is given, it will still be used
                for field, values in remaining_criteria.items():
                    if not field.startswith("port."):
                        break

                base_field = field.split(".")[0]
                logger.debug(
                    "No usable criteria get uid list from Base field: %s", base_field
                )
                partial_result = self.r.sunion(*self.r.keys(f"{base_field}:*"))

        # 3) Finally using the rest of criterais.
        for field, values in remaining_criteria.items():
            if not isinstance(values, list):
                values = [values]

            for value in values:
                parts = field.split(".")
                base_field = parts[0]
                suffix = parts[1] if len(parts) > 1 else ""
                matching_uids = set()

                # handle .like / .lk / .begin / .bg
                if suffix in ("like", "lk", "begin", "bg", "not", "nt"):
                    # substring = value.rstrip("*")
                    for key in self.r.scan_iter(f"{base_field}:*"):
                        val = key.split(":", 2)[1]
                        # If NOT is asked... we forgot this key
                        """if suffix in ("not", "nt") and value not in val:
                            # For NOT we need to get all the keys matching from the partials results...
                            # Then fetch the keys from these uid that are not matching the "pattern".
                            # print(partial_result)
                            # print(val)
                            matching_uids.update(
                                self.r.smembers(key).intersection(partial_result)
                            )
                        """
                        # IF like or begin we select it.
                        if (suffix in ("like", "lk") and value in val) or (
                            suffix in ("begin", "bg") and val.startswith(value)
                        ):
                            matching_uids.update(
                                self.r.smembers(key).intersection(partial_result)
                            )
                    partial_result = partial_result.intersection(matching_uids)
                else:
                    # exact match
                    uids = self.r.smembers(f"{base_field}:{value}")
                    partial_result = partial_result.intersection(uids)

        return list(partial_result)

    def get_ip_info(self, ip):
        """
        Get info for a given IP
        """

        uids = self.r.smembers(f"ip:{ip}")
        pipe = self.r.pipeline()
        for uid in uids:
            pipe.hgetall(f"doc:{uid}")
        results_raw = pipe.execute()
        results = {}
        for uid, data in zip(uids, results_raw):
            results[uid] = {
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
            }
        return results

    def get_ip_from_uids(self, uid_list):
        """
        Input: a dict of uid
        output: a dict of IP with containing related UID

        """

        keys = [f"uid:{uid}" for uid in uid_list]
        pipe = self.r.pipeline()

        for key in keys:
            pipe.get(key)

        ips = pipe.execute()
        ip_map = {}

        for uid, ip in zip(uid_list, ips):
            if ip:
                if ip in ip_map:
                    if isinstance(ip_map[ip], list):
                        ip_map[ip].append(uid)
                    else:
                        ip_map[ip] = [ip_map[ip], uid]
                else:
                    ip_map[ip] = [uid]
        return ip_map
