#!/bin/env python

"""
This is the main module for searching using kvrocks.
It contains all the logic to find something.
"""

try:
    from .timeutils import utcnow_iso
except ImportError:
    from timeutils import utcnow_iso
from datetime import datetime, timezone
import ipaddress
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
        return utcnow_iso()

    @staticmethod
    def normalize_timestamp(value):
        """
        Convert known timestamp formats to epoch seconds.
        """
        if value is None:
            return None

        if isinstance(value, (int, float)):
            timestamp = float(value)
        else:
            value = str(value).strip()
            if not value:
                return None

            try:
                timestamp = float(value)
            except ValueError:
                try:
                    if value.endswith("Z"):
                        value = f"{value[:-1]}+00:00"
                    date_value = datetime.fromisoformat(value)
                    if date_value.tzinfo is None:
                        date_value = date_value.replace(tzinfo=timezone.utc)
                    timestamp = date_value.timestamp()
                except ValueError:
                    return None

        if timestamp > 1_000_000_000_000:
            timestamp = timestamp / 1000
        if timestamp < 0:
            return None
        return int(timestamp)

    @classmethod
    def normalize_seen_range(cls, first_seen, last_seen):
        """
        Normalize first_seen/last_seen as an ordered epoch-second interval.
        """
        first_seen = cls.normalize_timestamp(first_seen)
        last_seen = cls.normalize_timestamp(last_seen)

        if first_seen is None and last_seen is None:
            return None, None
        if first_seen is None:
            first_seen = last_seen
        if last_seen is None:
            last_seen = first_seen
        if first_seen > last_seen:
            first_seen, last_seen = last_seen, first_seen
        return first_seen, last_seen

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

    def get_indexed_values(self, field, prefix="", limit=100):
        """
        Return distinct indexed values for one field, optionally filtered by prefix.
        """
        field = str(field or "").strip().lower()
        if not field:
            return []

        prefix = str(prefix or "").strip().lower()
        pattern = f"{field}:{prefix}*" if prefix else f"{field}:*"
        values = []
        seen = set()
        for key in self.r.scan_iter(match=pattern, count=min(max(limit, 1), 1000)):
            value = key.split(":", 1)[1].strip().lower()
            if not value or value in seen:
                continue
            seen.add(value)
            values.append(value)
            if len(values) >= limit:
                break
        return values

    def add_documents_batch(self, docs, batch_size=10000, include_tags=True):
        """
        insert documents into the kvrocks.
        Each doc: dict with keys:
          uid, ip, parsed search fields

        it does "batch insertions", up to 10K per insert by default
        """

        keywords = [
            # "ip",
            "net",
            # "as",
            # "as_number",
            # "as_name",
            # "as_description",
            # "as_country",
            "fqdn",
            "fqdn_requested",
            "host",
            "domain",
            "domain_requested",
            "tld",
            "tag",
            # "url_path",
            "port",
            # "protocol",
            "http_title",
            "http_favicon_path",
            "http_favicon_mmhash",
            "http_favicon_md5",
            "http_favicon_sha256",
            # "http_filename",
            "http_cookiename",
            "http_etag",
            "http_server",
            # "email",
            "x509_issuer",
            "x509_md5",
            "x509_sha1",
            "x509_sha256",
            "x509_subject",
            "x509_san",
            # "time_filter_before_after",
            # "ssh_fingerprint",
            # "ttl_count",
            # "hsh"
            "banner",
        ]
        if not include_tags:
            keywords.remove("tag")

        for i in range(0, len(docs), batch_size):
            batch = docs[i : i + batch_size]
            existing_pipe = self.r.pipeline(transaction=False)
            for doc in batch:
                existing_pipe.hgetall(f"doc:{doc['uid']}")
            existing_docs = existing_pipe.execute()

            existing_values_pipe = self.r.pipeline(transaction=False)
            for doc in batch:
                uid = doc["uid"]
                for field in keywords:
                    existing_values_pipe.smembers(f"{field}s:{uid}")
            existing_values = existing_values_pipe.execute()

            pipe = self.r.pipeline(transaction=False)
            existing_values_iter = iter(existing_values)
            for doc, existing in zip(batch, existing_docs):
                uid = doc["uid"]
                ip = doc["ip"]

                # http_servers = doc.get("http_servers, [])
                # http_cookies = doc.get("http_cookies", [])
                # http_titles = doc.get("http_titles", [])
                last_seen = doc.get("last_seen")  # Document last time scanned.

                uid_key = f"doc:{uid}"
                first_seen = doc.get("first_seen", last_seen)
                first_seen, last_seen = self.normalize_seen_range(first_seen, last_seen)

                if existing:
                    # For the same UID ( meaning same scan result hsh256)
                    # we recompute last seen and first seen.
                    # We do like that because if case of insert bulk
                    existing_first_seen = self.normalize_timestamp(
                        existing.get("first_seen")
                    )
                    existing_last_seen = self.normalize_timestamp(existing.get("last_seen"))
                    if existing_first_seen is not None:
                        first_seen = (
                            existing_first_seen
                            if first_seen is None
                            else min(existing_first_seen, first_seen)
                        )
                    if existing_last_seen is not None:
                        last_seen = (
                            existing_last_seen
                            if last_seen is None
                            else max(existing_last_seen, last_seen)
                        )
                    first_seen, last_seen = self.normalize_seen_range(
                        first_seen, last_seen
                    )

                # Set the "LastSeen/FirstSeen" Index
                if first_seen is not None and last_seen is not None:
                    pipe.zadd("last_seen_index", {uid: last_seen})
                    pipe.zadd("first_seen_index", {uid: first_seen})

                # Store hashset uid
                doc_mapping = {"ip": ip}
                if first_seen is not None and last_seen is not None:
                    doc_mapping["first_seen"] = str(first_seen)
                    doc_mapping["last_seen"] = str(last_seen)
                pipe.hset(uid_key, mapping=doc_mapping)

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
                # Generic indexing for any othe keyword
                # uid = unique identifier for the entry
                for field in keywords:
                    previous_values = next(existing_values_iter, set()) or set()
                    for previous_value in previous_values:
                        if previous_value:
                            pipe.srem(f"{field}:{previous_value}", uid)
                    pipe.delete(f"{field}s:{uid}")

                    values = doc.get(field, [])
                    # print(f"{field} - {values} - {uid}")
                    # We have still NONE in table
                    for v in values:
                        if v:
                            v = v.lower()
                            # print(f"{field} - {v} - {uid}")
                            pipe.sadd(f"{field}:{v}", uid)
                            pipe.sadd(f"{field}s:{uid}", v)
            pipe.execute()

    def replace_field_values_batch(self, field, docs, batch_size=10000):
        """
        Replace one multi-value field index for existing documents.

        This is used for lightweight reindex operations such as recomputing
        tags without touching the rest of the stored Kvrocks document indexes.
        """
        field = str(field or "").strip()
        if not field:
            raise ValueError("Field name is required")

        for i in range(0, len(docs), batch_size):
            normalized_batch = []
            for doc in docs[i : i + batch_size]:
                uid = str(doc.get("uid") or "").strip()
                if not uid:
                    continue

                raw_values = doc.get(field, []) or []
                if not isinstance(raw_values, list):
                    raw_values = [raw_values]

                values = []
                seen = set()
                for value in raw_values:
                    candidate = str(value).strip().lower()
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    values.append(candidate)

                normalized_batch.append({"uid": uid, field: values})

            if not normalized_batch:
                continue

            existing_pipe = self.r.pipeline(transaction=False)
            for doc in normalized_batch:
                existing_pipe.smembers(f"{field}s:{doc['uid']}")
            existing_values = existing_pipe.execute()

            pipe = self.r.pipeline(transaction=False)
            for doc, previous_values in zip(normalized_batch, existing_values):
                uid = doc["uid"]
                for value in previous_values or []:
                    candidate = str(value).strip().lower()
                    if candidate:
                        pipe.srem(f"{field}:{candidate}", uid)

                pipe.delete(f"{field}s:{uid}")
                for value in doc[field]:
                    pipe.sadd(f"{field}:{value}", uid)
                    pipe.sadd(f"{field}s:{uid}", value)
            pipe.execute()

    def get_uids_by_time_range(self, from_ts, to_ts):
        """
        Return document UIDs whose [first_seen, last_seen] overlaps the range.
        """
        from_ts, to_ts = self.normalize_seen_range(from_ts, to_ts)
        if from_ts is None or to_ts is None:
            return set()

        seen_after_start = set(
            self.r.zrangebyscore("last_seen_index", from_ts, "+inf")
        )
        started_before_end = set(
            self.r.zrangebyscore("first_seen_index", "-inf", to_ts)
        )
        return seen_after_start.intersection(started_before_end)

    def get_uids_by_last_seen_range(self, from_ts, to_ts):
        """
        Return document UIDs whose last_seen is inside the range.
        """
        from_ts, to_ts = self.normalize_seen_range(from_ts, to_ts)
        if from_ts is None or to_ts is None:
            return set()
        return set(self.r.zrangebyscore("last_seen_index", from_ts, to_ts))

    def _filter_uids_by_network(self, uids, network):
        """
        Keep only UIDs whose indexed IP is inside the requested CIDR.
        """
        uids = list(uids or [])
        if not uids:
            return set()

        pipe = self.r.pipeline(transaction=False)
        for uid in uids:
            pipe.get(f"uid:{uid}")
        ip_values = pipe.execute()

        filtered = set()
        for uid, ip_value in zip(uids, ip_values):
            if not ip_value:
                continue
            try:
                if ipaddress.ip_address(ip_value) in network:
                    filtered.add(uid)
            except ValueError:
                continue
        return filtered

    def _get_uids_for_net_value(self, net_val, scoped_uids=None):
        """
        Resolve one CIDR query, including masks not directly indexed in Kvrocks.
        """
        try:
            network = ipaddress.ip_network(str(net_val).strip(), strict=False)
        except ValueError:
            return set()

        candidate_uids = set()
        prefixlen = network.prefixlen

        if 16 <= prefixlen <= 24:
            candidate_uids = set(self.r.smembers(f"net:{network.with_prefixlen}"))
        elif prefixlen > 24:
            parent = network.supernet(new_prefix=24)
            candidate_uids = set(self.r.smembers(f"net:{parent.with_prefixlen}"))
        else:
            for subnet in network.subnets(new_prefix=16):
                candidate_uids.update(self.r.smembers(f"net:{subnet.with_prefixlen}"))

        if scoped_uids is not None:
            candidate_uids.intersection_update(set(scoped_uids))

        if prefixlen < 16 or prefixlen > 24:
            candidate_uids = self._filter_uids_by_network(candidate_uids, network)

        return candidate_uids

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

        if not remaining_criteria:
            return []

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
                uids_net.update(self._get_uids_for_net_value(net_val))

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
                field = None
                for field, values in remaining_criteria.items():
                    if not field.startswith("port."):
                        break

                if field is None:
                    return []

                base_field = field.split(".")[0]
                logger.debug(
                    "No usable criteria get uid list from Base field: %s", base_field
                )
                matching_keys = self.r.keys(f"{base_field}:*")
                if not matching_keys:
                    return []
                partial_result = self.r.sunion(*matching_keys)

        if partial_result is None:
            return []

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
                        val = key.split(":", 1)[1]
                        # If NOT is needed here later, use the already scoped
                        # partial_result to subtract matching keys instead of
                        # rescanning every UID value ad hoc.
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

        # return an list of UUIDs
        return list(partial_result or [])

    def get_uids_by_criteria_scoped(self, criteria: dict, scoped_uids):
        """
        Return UIDs matching criteria inside an already selected UID scope.
        """
        partial_result = set(scoped_uids or [])
        if not criteria or not partial_result:
            return []

        remaining_criteria = dict(criteria)
        scoped_base = set()

        if "ip" in remaining_criteria:
            ip_vals = remaining_criteria.pop("ip")
            if not isinstance(ip_vals, list):
                ip_vals = [ip_vals]
            for ip in ip_vals:
                scoped_base.update(self.r.smembers(f"ip:{ip}"))

        if "net" in remaining_criteria:
            net_vals = remaining_criteria.pop("net")
            if not isinstance(net_vals, list):
                net_vals = [net_vals]
            for net_val in net_vals:
                scoped_base.update(self._get_uids_for_net_value(net_val, partial_result))

        if scoped_base:
            partial_result = partial_result.intersection(scoped_base)
            if not partial_result:
                return []
        elif "ip" in criteria or "net" in criteria:
            return []

        for field, values in remaining_criteria.items():
            if not isinstance(values, list):
                values = [values]

            field_uids = set()
            for value in values:
                parts = field.split(".")
                base_field = parts[0]
                suffix = parts[1] if len(parts) > 1 else ""

                if suffix in ("like", "lk", "begin", "bg", "not", "nt"):
                    for key in self.r.scan_iter(f"{base_field}:*"):
                        val = key.split(":", 1)[1]
                        if (suffix in ("like", "lk") and value in val) or (
                            suffix in ("begin", "bg") and val.startswith(value)
                        ):
                            field_uids.update(
                                self.r.smembers(key).intersection(partial_result)
                            )
                else:
                    field_uids.update(
                        self.r.smembers(f"{base_field}:{value}").intersection(
                            partial_result
                        )
                    )

            partial_result = partial_result.intersection(field_uids)
            if not partial_result:
                break

        return list(partial_result or [])

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
                "first_seen": self.normalize_timestamp(data.get("first_seen")),
                "last_seen": self.normalize_timestamp(data.get("last_seen")),
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

    def get_requested_hostnames_for_uids(self, uid_list):
        """
        Return requested hostnames indexed for each UID.
        """
        uid_list = [str(uid) for uid in uid_list or [] if uid]
        if not uid_list:
            return {}

        pipe = self.r.pipeline()
        for uid in uid_list:
            pipe.smembers(f"fqdn_requesteds:{uid}")

        results = pipe.execute()
        return {
            uid: sorted(
                {
                    str(hostname or "").strip().lower()
                    for hostname in hostnames or []
                    if str(hostname or "").strip()
                }
            )
            for uid, hostnames in zip(uid_list, results)
        }

    def get_timestamp_from_uid(self, uid):
        """
        This Function ask doc timestamp ( last first)

        :param uid: Document UUID in kvrocks

        127.0.0.1:6666> HGETALL doc:a64dd35e-f1d1-59cf-bd71-dff5affffd8a
            1) "first_seen"
            2) "1767778159"
            3) "ip"
            4) "104.18.34.219"
            5) "last_seen"
            6) "1767778159"

        """
        pipe = self.r.pipeline()
        pipe.hgetall(f"doc:{uid}")
        results_raw = pipe.execute()
        data = results_raw[0] if results_raw else {}
        first_seen, last_seen = self.normalize_seen_range(
            data.get("first_seen"), data.get("last_seen")
        )
        return {
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def get_timestamp_for_ip(self, ip):
        """
        This functions ask timestamp for a given IP

        :param self: Description
        :param ip: Description

        127.0.0.1:6666> smembers ip:146.0.178.196
            1) "0512bce3-96ef-54cc-861d-3eca8056eb1f"
            2) "404bd035-be3a-56b7-b517-f2620614969a"
            3) "4146fc22-7d71-572f-80c1-d89da512d8aa"
            4) "4388792d-2642-54e0-942b-f59f307c1c4c"
            ...

        """
        max_first_seen = 9999999999999
        max_last_seen = -1

        uids = self.r.smembers(f"ip:{ip}")
        pipe = self.r.pipeline()
        for uid in uids:
            pipe.hgetall(f"doc:{uid}")
        results_raw = pipe.execute()
        results = {}
        for uid, data in zip(uids, results_raw):
            first_seen, last_seen = self.normalize_seen_range(
                data.get("first_seen"), data.get("last_seen")
            )
            results[uid] = {
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
            if first_seen is not None:
                max_first_seen = min(first_seen, max_first_seen)
            if last_seen is not None:
                max_last_seen = max(last_seen, max_last_seen)
        results["max_seen"] = max_last_seen if max_last_seen != -1 else None
        results["min_seen"] = max_first_seen if max_first_seen != 9999999999999 else None
        return results
