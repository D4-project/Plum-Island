"""Shared Boolean grammar and read-only candidate planner regressions."""

import copy
import itertools
import json
import pickle
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test import test_kvrocks_search as search_fixtures
from test.test_kvrocks_search import (
    isolated_search_view,
    make_indexer,
    sample_indexer,
)
from search_plan import CandidatePlanner, build_plan
from search_query import iter_criteria, tokenize_query
from tagrules import analyze_header_dependencies, document_matches_criteria_groups

# pylint: disable=missing-function-docstring,protected-access


class ParenthesizedSearchTest(unittest.TestCase):
    """Compare compact queries against expanded equivalents on real index logic."""

    def setUp(self):
        self.indexer = make_indexer(
            {
                "domain_requested:circl.lu": {"a", "b"},
                "net:185.194.93.0/24": {"c", "d"},
                "net:185.194.94.0/24": {"e", "f"},
                "tag:lang:php": {"a", "c", "e", "outside"},
                "port:443": {"a", "b", "c"},
                "port:80": {"d", "e", "f"},
                "http_server:nginx": {"a", "c", "d"},
            }
        )
        self.view = isolated_search_view(self.indexer)
        self.compact = (
            "(domain_requested:circl.lu or net:185.194.93.0/24 "
            "or net:185.194.94.0/24) and tag:lang:php"
        )
        self.expanded = (
            "domain_requested:circl.lu and tag:lang:php "
            "or net:185.194.93.0/24 and tag:lang:php "
            "or net:185.194.94.0/24 and tag:lang:php"
        )

    def parse(self, query):
        parsed, valid, error = self.view.parse_query(query, True, True)
        self.assertTrue(valid, error)
        return parsed

    def match(self, query, scope=None):
        return self.view._get_matching_uids(self.indexer, self.parse(query), scope)

    def test_compact_expanded_reordered_and_scoped_equivalence(self):
        queries = [
            self.compact,
            self.expanded,
            "tag:lang:php AND " + self.compact.rsplit(" and ", 1)[0],
        ]
        for query in queries:
            with self.subTest(query=query):
                self.assertEqual(self.match(query), {"a", "c", "e"})
                self.assertEqual(self.match(query, {"b", "c", "e"}), {"c", "e"})
                self.assertEqual(self.match(query, set()), set())

    def test_negation_common_positive_bound_and_sibling_groups(self):
        cases = {
            "(port:443 OR port:80) NOT http_server:nginx": {"b", "e", "f"},
            "(port:443 NOT http_server:nginx OR port:80) tag:lang:php": {"e"},
            "(NOT port:80 OR port:443) tag:lang:php": {"a", "c", "outside"},
            "tag:lang:php (NOT port:80 OR NOT http_server:nginx)": {
                "a",
                "c",
                "e",
                "outside",
            },
            "(port:443 OR port:80) (http_server:nginx OR tag:lang:php)": {
                "a",
                "c",
                "d",
                "e",
            },
            "port:80 OR port:443 tag:lang:php": {"a", "c", "d", "e", "f"},
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                self.assertEqual(self.match(query), expected)

    def test_quoted_parentheses_ipv6_colons_and_directives(self):
        query = '(http_title:"(hello OR world)" OR ip:2001:db8::1) debug since:3'
        self.assertEqual(
            list(iter_criteria(self.parse(query))),
            [{"http_title": ["(hello OR world)"]}, {"ip": ["2001:db8::1"]}],
        )
        self.assertEqual(
            list(
                iter_criteria(
                    self.parse(
                        r'(banner:hello\(world\) OR http_headval:server:"nginx:edge")'
                    )
                )
            ),
            [{"banner": ["hello(world)"]}, {"http_headval": ["server:nginx:edge"]}],
        )
        self.assertEqual(
            [t.kind for t in tokenize_query("(port:80)")], ["(", "TERM", ")"]
        )
        parsed = self.parse(self.compact)
        self.assertEqual(pickle.loads(pickle.dumps(parsed)), parsed)

    def test_invalid_syntax_fails_without_backend_calls(self):
        queries = [
            "()",
            "( )",
            "((port:80))",
            "port:80 (port:443 (port:22))",
            "(port:80",
            "port:80)",
            "(port:80))",
            "(port:80 OR)",
            "(OR port:80)",
            "(AND port:80)",
            "port:80 AND",
            "port:80 AND AND port:443",
            "(port:80) OR",
            "(port:80) AND ()",
            "NOT (port:80)",
            "(NOT port:80)",
            "(port:80 OR NOT port:443)",
            "(debug)",
            "(since:3)",
            "(port:80 NOT debug)",
            "(port:80 NOT since:3)",
            '(http_title:"unterminated)',
            "(unknown:value)",
        ]
        for query in queries:
            with self.subTest(query=query):
                self.assertFalse(self.view.parse_query(query, True, True)[1])
        self.assertEqual(self.indexer.r.direct_reads, [])
        self.assertEqual(self.indexer.r.batches, [])

    def test_candidate_order_changes_with_cardinalities(self):
        parsed = self.parse(self.compact)
        for tags, expected_seed in [
            ({"a"}, "tag:lang:php"),
            ({"a", *(f"other{i}" for i in range(20))}, "domain_requested:circl.lu"),
        ]:
            self.indexer.r.sets["tag:lang:php"] = tags
            self.indexer.r.direct_reads.clear()
            diagnostic = SimpleNamespace()
            planner = CandidatePlanner(self.indexer, parsed, diagnostics=diagnostic)
            self.assertEqual(planner.execute(), {"a"})
            self.assertEqual(self.indexer.r.direct_reads[0], expected_seed)
            self.assertEqual(diagnostic.planner["counter_keys"], 4)
            text = json.dumps(diagnostic.planner)
            self.assertNotIn("circl.lu", text)
            self.assertNotIn("185.194", text)
            self.assertNotIn("lang:php", text)
        self.assertTrue(
            all(not transaction for transaction, _ in self.indexer.r.batches)
        )

    def test_shared_predicates_factored_and_no_cartesian_expansion(self):
        self.assertEqual(self.match(self.expanded), {"a", "c", "e"})
        self.assertEqual(self.indexer.r.direct_reads.count("tag:lang:php"), 1)
        query = " ".join("(port:80 OR port:443)" for _ in range(30))
        parsed = self.parse(query)
        self.assertEqual(len(list(iter_criteria(parsed))), 60)
        self.assertEqual(
            build_plan(parsed), build_plan(self.parse("port:80 OR port:443"))
        )
        self.assertEqual(self.match(query), {"a", "b", "c", "d", "e", "f"})

    def test_reused_predicate_cache_does_not_leak_branch_scope(self):
        query = "port:80 tag:lang:php OR port:443 tag:lang:php http_server:nginx"
        self.assertEqual(self.match(query), {"a", "c", "e"})
        self.assertEqual(self.indexer.r.direct_reads.count("tag:lang:php"), 1)

    def test_cardinality_is_only_hint_and_empty_seed_skips_expensive_reads(self):
        with patch.object(self.indexer.r, "scard", return_value=0):
            self.assertEqual(self.match("tag:lang:php"), {"a", "c", "e", "outside"})
        self.indexer.r.direct_reads.clear()
        self.assertEqual(self.match("http_server.lk:nginx tag:type:missing"), set())
        self.assertEqual(self.indexer.r.direct_reads, ["tag:type:missing"])
        self.assertEqual(self.indexer.r.scans, [])

    def test_existing_flat_queries_match_original_scoped_and_unscoped_indexer(self):
        self.indexer = sample_indexer()
        self.view = isolated_search_view(self.indexer)
        terms = [
            "ip:8.8.8.8",
            "net:9.9.9.0/24",
            "port:443",
            "port:missing",
            "http_server.lk:nginx",
            "http_server.bg:proxy",
            "http_server.not:apache",
            "http_headval:x-powered-by.lk:php",
            "http_headval:x-other:php/8",
        ]
        for pair in itertools.product(terms, repeat=2):
            query = " ".join(pair)
            parsed = self.parse(query)
            original = copy.deepcopy(parsed)
            for scope in (None, {"u1", "u3"}, set()):
                with self.subTest(query=query, scope=scope):
                    expected = (
                        self.indexer.get_uids_by_criteria(parsed[0])
                        if scope is None
                        else self.indexer.get_uids_by_criteria_scoped(parsed[0], scope)
                    )
                    self.assertEqual(self.match(query, scope), set(expected))
                    self.assertEqual(parsed, original)

    def test_grouped_tag_engine_and_header_dependencies(self):
        parsed = self.parse(
            "(http_header:x-public OR http_headval:x-powered-by.lk:php) "
            "port:443 NOT http_header:x-private"
        )
        self.assertEqual(
            analyze_header_dependencies(parsed),
            {
                "exact": {"x-public": False, "x-powered-by": True, "x-private": False},
                "ambiguous": [],
            },
        )
        for document, expected in [
            ({"port": [443], "http_header": ["x-public"]}, True),
            ({"port": [443], "http_headval": ["x-powered-by:php 8"]}, True),
            ({"port": [80], "http_header": ["x-public"]}, False),
            ({"port": [443], "http_header": ["x-public", "x-private"]}, False),
        ]:
            self.assertEqual(
                document_matches_criteria_groups(document, parsed), expected
            )

    def test_paging_export_history_scopes_and_debug_transport(self):
        # pylint: disable=too-many-locals
        fixture = search_fixtures.SearchConsumerTest()
        fixture.setUp()
        view, indexer = fixture.view, fixture.indexer
        for number in range(105):
            fixture.add_doc(
                f"extra{number}", f"10.0.0.{number + 1}", 200, 250, "nginx", "443"
            )
        compact = "(http_server:nginx OR http_server:apache) port:443"
        expanded = "http_server:nginx port:443 OR http_server:apache port:443"

        def comparable(response):
            response.pop("processingTimeMs", None)
            return response

        full = comparable(view.execute_search(compact, 200, 300))
        self.assertEqual(full, comparable(view.execute_search(expanded, 200, 300)))
        self.assertEqual(len(full["results"]), 108)
        first = comparable(view.execute_search_page(compact, 200, 300))
        self.assertEqual(
            first, comparable(view.execute_search_page(expanded, 200, 300))
        )
        self.assertEqual(len(first["results"]), 100)
        kwargs = {
            "cursor_ts": first["pagination"]["next_cursor"],
            "seen_ips": set(first["results"]),
        }
        second = comparable(view.execute_search_page(compact, 200, 300, **kwargs))
        self.assertEqual(
            second, comparable(view.execute_search_page(expanded, 200, 300, **kwargs))
        )
        self.assertEqual(len(second["results"]), 7)
        self.assertNotIn("1.1.1.1", first["results"] | second["results"])
        self.assertIn("1.1.1.1", full["results"])
        groups, _, _ = view.parse_query(compact)
        self.assertEqual(view._get_matching_uids(indexer, groups, {"u1", "u2"}), {"u1"})
        transports = []
        for query in (compact, compact + " debug"):
            indexer.r.direct_reads.clear()
            indexer.r.scans.clear()
            indexer.r.batches.clear()
            result = view.execute_search_page(query, 200, 300)
            transports.append(
                copy.deepcopy(
                    (indexer.r.direct_reads, indexer.r.scans, indexer.r.batches)
                )
            )
            debug = result.pop("debug", None)
            self.assertEqual(comparable(result), first)
        self.assertEqual(transports[0], transports[1])
        self.assertEqual(debug["planner"]["counter_keys"], 3)
        self.assertEqual(debug["kvrocks"]["commands"]["SCARD"]["pipeline_calls"], 3)


if __name__ == "__main__":
    unittest.main()
