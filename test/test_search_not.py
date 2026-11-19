"""Unary NOT regressions across parsing, UID matching, paging and tag rules."""

import copy
import unittest

from test.test_kvrocks_search import isolated_search_view, make_indexer
from tagrules import analyze_header_dependencies, document_matches_criteria_groups

# pylint: disable=missing-function-docstring,protected-access


class SearchNotTest(unittest.TestCase):
    """An exclusion applies to matching documents, independently within each OR."""

    def setUp(self):
        self.indexer = make_indexer()
        self.view = isolated_search_view(self.indexer)
        self.add_doc("mikrotik", "8.8.8.8", ["type:router", "vendor:mikrotik"])
        self.add_doc(
            "cisco", "8.8.8.8", ["type:router", "vendor:cisco"], server="apache"
        )
        self.add_doc("unknown", "9.9.9.9", ["type:router"], last=300)
        self.add_doc("switch", "1.1.1.1", ["type:switch", "vendor:mikrotik"])
        self.add_doc(
            "both", "4.4.4.4", ["type:router", "vendor:cisco", "vendor:mikrotik"]
        )
        self.add_doc("span", "6.6.6.6", ["type:router", "vendor:cisco"], last=350)

    def add_doc(
        self, uid, ip, tags, last=250, server="nginx"
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        client = self.indexer.r
        for key in (
            "all_uids",
            f"ip:{ip}",
            "port:443",
            f"http_server:{server}",
            *(f"tag:{tag}" for tag in tags),
        ):
            client.sets.setdefault(key, set()).add(uid)
        client.sets.setdefault("all_ips", set()).add(ip)
        client.sets[f"tags:{uid}"] = set(tags)
        client.strings[f"uid:{uid}"] = ip
        client.hashes[f"doc:{uid}"] = {"ip": ip, "first_seen": 100, "last_seen": last}
        client.sorted_sets.setdefault("first_seen_index", {})[uid] = 100
        client.sorted_sets.setdefault("last_seen_index", {})[uid] = last

    @staticmethod
    def uids(response):
        return {uid for values in response["results"].values() for uid in values}

    def test_router_exclusion_case_insensitive_and_same_ip_history(self):
        query = "tag:type:router and not tag:vendor:mikrotik"
        groups, valid, error = self.view.parse_query(query)
        self.assertTrue(valid, error)
        self.assertEqual(
            groups, [{"tag": ["type:router"], "!tag": ["vendor:mikrotik"]}]
        )
        full = self.view.execute_search(query, 200, 300)
        page = self.view.execute_search_page(query + " debug", 200, 300)
        self.assertEqual(self.uids(full), {"cisco", "unknown", "span"})
        self.assertEqual(self.uids(page), {"cisco", "unknown"})
        self.assertEqual(list(page["results"]), ["9.9.9.9", "8.8.8.8"])
        self.assertEqual(page["results"]["8.8.8.8"], ["cisco"])
        self.assertEqual(page["timestamps"]["8.8.8.8"]["max_seen"], 250)
        self.assertEqual(page["debug"]["counts"]["matched_uids"], 2)
        uppercase = self.view.execute_search(
            "TAG:TYPE:ROUTER AND NOT TAG:VENDOR:MIKROTIK", 200, 300
        )
        self.assertEqual(self.uids(uppercase), self.uids(full))

    def test_exclusions_are_per_or_group_and_repeated_values_exclude_any(self):
        cases = {
            "tag:type:router NOT tag:vendor:mikrotik OR tag:type:switch": {
                "cisco",
                "unknown",
                "span",
                "switch",
            },
            "tag:type:router NOT tag:vendor:mikrotik NOT tag:vendor:cisco": {"unknown"},
            "NOT tag:vendor:mikrotik tag:type:router": {"cisco", "unknown", "span"},
            "tag:type:router NOT tag:type:router": set(),
            "tag:type:router NOT tag:vendor:missing": {
                "mikrotik",
                "cisco",
                "unknown",
                "both",
                "span",
            },
            "tag:type:router NOT http_server.lk:apache": {
                "mikrotik",
                "unknown",
                "both",
                "span",
            },
            "tag:type:router NOT ip:8.8.8.8": {"unknown", "both", "span"},
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                response = self.view.execute_search(query, 200, 300)
                self.assertTrue(response["status"], response["msg_error"])
                self.assertEqual(self.uids(response), expected)

    def test_missing_positive_candidates_skip_exclusion_reads_and_keep_inputs(self):
        groups, valid, _ = self.view.parse_query(
            "tag:type:missing NOT tag:vendor:mikrotik"
        )
        self.assertTrue(valid)
        original = copy.deepcopy(groups)
        scope = {"mikrotik", "unknown"}
        self.assertEqual(
            self.view._get_matching_uids(self.indexer, groups, scope), set()
        )
        self.assertEqual(groups, original)
        self.assertEqual(scope, {"mikrotik", "unknown"})
        self.assertNotIn("tag:vendor:mikrotik", self.indexer.r.direct_reads)

    def test_quoted_values_directives_and_invalid_not_operands(self):
        groups, valid, error = self.view.parse_query(
            'debug port:443 NOT http_title:"NOT AND OR" since:3',
            allow_debug_directive=True,
            allow_since_directive=True,
        )
        self.assertTrue(valid, error)
        self.assertEqual(groups, [{"port": ["443"], "!http_title": ["NOT AND OR"]}])
        groups, valid, _ = self.view.parse_query(
            "port:443 NOT http_headval:x-powered-by.lk:php"
        )
        self.assertTrue(valid)
        self.assertEqual(
            groups, [{"port": ["443"], "!http_headval.lk": ["x-powered-by:php"]}]
        )
        for query in (
            "NOT",
            "NOT tag:vendor:mikrotik",
            "port:443 NOT",
            "port:443 NOT OR port:80",
            "port:443 NOT AND tag:type:router",
            "port:443 NOT NOT tag:type:router",
            "port:443 NOT debug tag:type:router",
            "port:443 NOT since:3 tag:type:router",
            "port:443 OR NOT tag:vendor:mikrotik",
            "port:443 NOT unknown:value",
            "port:443 NOT tag.lk:vendor",
            "port:443 NOT http_server.not:nginx",
            "port:443 NOT (tag:type:router OR tag:type:switch)",
            'port:443 NOT http_title:"unfinished',
        ):
            with self.subTest(query=query):
                self.assertFalse(self.view.parse_query(query, True, True)[1])

    def test_excluded_uids_do_not_consume_page_limit_or_break_continuation(self):
        for number in range(105):
            self.add_doc(
                f"extra{number}", f"10.0.0.{number + 1}", ["type:router"], last=280
            )
            self.add_doc(
                f"excluded{number}",
                f"10.1.0.{number + 1}",
                ["type:router", "vendor:mikrotik"],
                last=290,
            )
        query = "tag:type:router AND NOT tag:vendor:mikrotik"
        first = self.view.execute_search_page(query, 200, 300)
        self.assertEqual(len(first["results"]), 100)
        self.assertEqual(first["pagination"]["next_cursor"], 300)
        self.assertTrue(first["pagination"]["stopped_in_window"])
        second = self.view.execute_search_page(
            query, 200, 300, cursor_ts=300, seen_ips=set(first["results"])
        )
        self.assertEqual(len(second["results"]), 7)
        self.assertFalse(set(first["results"]) & set(second["results"]))
        self.assertFalse(second["pagination"]["has_more"])
        combined = self.uids(first) | self.uids(second)
        self.assertEqual(
            combined, {"cisco", "unknown", *(f"extra{n}" for n in range(105))}
        )

    def test_tag_rule_matching_and_negative_header_dependencies(self):
        groups, valid, _ = self.view.parse_query(
            "port:443 NOT http_server.lk:apache NOT http_server.bg:proxy"
        )
        self.assertTrue(valid)
        for servers, expected in (
            ([], True),
            (["nginx"], True),
            (["Apache"], False),
            (["nginx", "proxy"], False),
        ):
            with self.subTest(servers=servers):
                self.assertEqual(
                    document_matches_criteria_groups(
                        {"port": [443], "http_server": servers}, groups
                    ),
                    expected,
                )
        self.assertFalse(document_matches_criteria_groups({"port": [80]}, groups))
        groups, valid, _ = self.view.parse_query(
            "port:443 NOT http_headval:x-powered-by:php NOT http_header:x-private"
        )
        self.assertTrue(valid)
        self.assertEqual(
            analyze_header_dependencies(groups),
            {"exact": {"x-powered-by": True, "x-private": False}, "ambiguous": []},
        )
        self.assertFalse(
            document_matches_criteria_groups(
                {"port": [443], "http_headval": ["x-powered-by:php"]}, groups
            )
        )


if __name__ == "__main__":
    unittest.main()
