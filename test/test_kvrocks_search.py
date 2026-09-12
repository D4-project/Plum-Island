"""Search semantics regression checks without external services."""

import ast
import copy
import logging
import re
import shlex
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# pylint: disable=missing-function-docstring,protected-access

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webapp/app/utils"))
from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position
from search_debug import (  # pylint: disable=wrong-import-position
    debug_requested,
    profile_search_page,
)


class MemoryPipeline:
    """Queue commands without passing through synchronous client methods."""

    def __init__(self, client, transaction):
        self.client = client
        self.transaction = transaction
        self.commands = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.commands.clear()

    def smembers(self, key):
        self.commands.append(("set", key))

    def get(self, key):
        self.commands.append(("string", key))

    def hgetall(self, key):
        self.commands.append(("hash", key))

    def execute(self):
        self.client.batches.append((self.transaction, list(self.commands)))
        results = []
        for kind, key in self.commands:
            if kind == "set":
                result = set(self.client.sets.get(key, set()))
            elif kind == "hash":
                result = dict(self.client.hashes.get(key, {}))
            else:
                result = self.client.strings.get(key)
            results.append(result)
        self.commands.clear()
        return results

    @property
    def command_stack(self):
        """Expose redis-py's queued-command shape for diagnostics."""
        names = {"set": "SMEMBERS", "string": "GET", "hash": "HGETALL"}
        return [((names[kind], key), {}) for kind, key in self.commands]


class MemoryClient:  # pylint: disable=too-many-instance-attributes
    """Minimal deterministic store with observable SCAN/read/pipeline calls."""

    def __init__(self, sets=None):
        self.sets = sets or {}
        self.strings = {}
        self.hashes = {}
        self.sorted_sets = {}
        self.direct_reads = []
        self.scans = []
        self.batches = []
        self.scan_keys = None

    def pipeline(self, transaction=True):
        return MemoryPipeline(self, transaction)

    def smembers(self, key):
        return self.execute_command("SMEMBERS", key)

    def scard(self, key):
        return self.execute_command("SCARD", key)

    def zrangebyscore(self, key, minimum, maximum):
        return self.execute_command("ZRANGEBYSCORE", key, minimum, maximum)

    def execute_command(self, command, key, *args):
        """Same dispatch point used by the real protocol client."""
        if command == "SMEMBERS":
            self.direct_reads.append(key)
            return set(self.sets.get(key, set()))
        if command == "SCARD":
            return len(self.sets.get(key, set()))
        if command == "ZRANGEBYSCORE":
            return {
                uid
                for uid, score in self.sorted_sets.get(key, {}).items()
                if float(args[0]) <= score <= float(args[1])
            }
        if command == "SCAN":
            return 0, self._scan_keys(key, *args)
        raise AssertionError(command)

    def scan_iter(self, match, count=None):
        yield from self.execute_command("SCAN", match, count)[1]

    def _scan_keys(self, match, count):
        self.scans.append((match, count))
        # Our fixtures need '*' and escaped literals, not character classes.
        pattern = ""
        chars = iter(match)
        for char in chars:
            if char == "\\":
                pattern += re.escape(next(chars, ""))
            elif char == "*":
                pattern += ".*"
            else:
                pattern += re.escape(char)
        keys = self.sets if self.scan_keys is None else self.scan_keys
        return [key for key in keys if re.fullmatch(pattern, key)]


def make_indexer(sets=None):
    indexer = KVrocksIndexer.__new__(KVrocksIndexer)
    indexer.r = MemoryClient(sets)
    return indexer


def sample_indexer():
    return make_indexer(
        {
            "http_server:nginx:edge": {"u1", "u2"},
            "http_server:proxy nginx": {"u2", "u3"},
            "http_server:apache": {"u4"},
            "http_servers:unrelated": {"not-a-uid"},
            "port:443": {"u1", "u3", "u4"},
            "port:80": {"u2"},
            "ip:8.8.8.8": {"u1", "u2"},
            "net:9.9.9.0/24": {"u3"},
            "http_headval:x-powered-by:php/8:release": {"u1", "u2"},
            "http_headval:x-powered-by:proxy php": {"u3"},
            "http_headval:x-other:php/8": {"u4"},
            "http_headval:x*:php": {"u1"},
            "http_headval:xyz:php": {"u4"},
        }
    )


class SearchMatchingTest(unittest.TestCase):
    """Preserve UID matching behavior independently of transport strategy."""

    def test_duplicate_scan_keys_missing_sets_and_no_matches(self):
        indexer = sample_indexer()
        indexer.r.scan_keys = [
            "http_server:nginx:edge",
            "http_server:nginx:edge",
            "http_server:nginx:missing",
        ]
        self.assertEqual(
            set(indexer.get_uids_by_criteria({"http_server.bg": ["nginx"]})),
            {"u1", "u2"},
        )
        empty = make_indexer({"http_server:apache": {"u1"}})
        self.assertEqual(
            empty.get_uids_by_criteria_scoped({"http_server.bg": ["nginx"]}, {"u1"}), []
        )
        self.assertEqual(empty.r.batches, [])
        self.assertEqual(empty.r.direct_reads, [])

    def test_modifier_aliases_and_exact_matches(self):
        cases = [
            ("like", "nginx", {"u1", "u2", "u3"}),
            ("lk", "nginx", {"u1", "u2", "u3"}),
            ("begin", "nginx", {"u1", "u2"}),
            ("bg", "nginx", {"u1", "u2"}),
            ("lk", ":edge", {"u1", "u2"}),
            ("bg", ":edge", set()),
            ("lk", "missing", set()),
            ("", "nginx:edge", {"u1", "u2"}),
            ("not", "nginx:edge", set()),
            ("nt", "nginx:edge", set()),
        ]
        for suffix, value, expected in cases:
            criteria = {"http_server" + (f".{suffix}" if suffix else ""): [value]}
            with self.subTest(criteria=criteria):
                indexer = sample_indexer()
                self.assertEqual(set(indexer.get_uids_by_criteria(criteria)), expected)
                self.assertEqual(
                    set(indexer.get_uids_by_criteria_scoped(criteria, {"u2", "u4"})),
                    expected & {"u2", "u4"},
                )

    def test_repeated_values_multifield_and_inputs_unchanged(self):
        indexer = sample_indexer()
        criteria = {"http_server.lk": ["nginx", "proxy"], "port": ["443"]}
        original = copy.deepcopy(criteria)
        scope = {"u1", "u2", "u3", "u4"}
        self.assertEqual(set(indexer.get_uids_by_criteria(criteria)), {"u3"})
        self.assertEqual(
            set(indexer.get_uids_by_criteria_scoped(criteria, scope)), {"u3"}
        )
        self.assertEqual(criteria, original)
        self.assertEqual(scope, {"u1", "u2", "u3", "u4"})
        self.assertEqual(indexer.get_uids_by_criteria_scoped(criteria, set()), [])
        self.assertEqual(indexer.get_uids_by_criteria_scoped(criteria, {"absent"}), [])
        self.assertEqual(indexer.get_uids_by_criteria({}), [])
        self.assertEqual(indexer.get_uids_by_criteria_scoped({}, scope), [])

    def test_ip_network_union_and_narrow_network_filter(self):
        indexer = sample_indexer()
        criteria = {
            "ip": ["8.8.8.8"],
            "net": ["9.9.9.0/24"],
            "http_server.lk": ["nginx"],
        }
        self.assertEqual(
            set(indexer.get_uids_by_criteria(criteria)), {"u1", "u2", "u3"}
        )
        self.assertEqual(
            set(indexer.get_uids_by_criteria_scoped(criteria, {"u2", "u3"})),
            {"u2", "u3"},
        )
        indexer.r.strings["uid:u3"] = "9.9.9.1"
        self.assertEqual(
            set(indexer.get_uids_by_criteria({"net": ["9.9.9.1/32"]})), {"u3"}
        )
        self.assertEqual(indexer.get_uids_by_criteria({"net": ["9.9.9.2/32"]}), [])

    def test_headers_exact_name_normalization_and_colons(self):
        indexer = sample_indexer()
        for suffix, expected in (("lk", {"u1", "u2", "u3"}), ("bg", {"u1", "u2"})):
            self.assertEqual(
                indexer._get_uids_for_http_headval("X-Powered-By:PHP", suffix), expected
            )
            self.assertEqual(
                indexer._get_uids_for_http_headval(
                    "x-powered-by:php", suffix, {"u2", "u4"}
                ),
                {"u2"},
            )
        self.assertEqual(
            indexer._get_uids_for_http_headval("x-powered-by:php/8:release"),
            {"u1", "u2"},
        )
        self.assertEqual(indexer._get_uids_for_http_headval("x*:php", "bg"), {"u1"})
        self.assertIn(
            r"http_headval:x\*:*", [pattern for pattern, _ in indexer.r.scans]
        )
        for raw in ("missing", ":php", "x:", "bad name:php", "x" * 129 + ":php"):
            self.assertEqual(indexer._get_uids_for_http_headval(raw, "lk"), set())
        self.assertEqual(indexer._get_uids_for_http_headval("x:php", "not"), set())
        criteria = {"http_headval.lk": ["x-powered-by:php", "x-powered-by:release"]}
        self.assertEqual(set(indexer.get_uids_by_criteria(criteria)), {"u1", "u2"})
        self.assertEqual(
            set(indexer.get_uids_by_criteria_scoped(criteria, {"u2"})), {"u2"}
        )


class SearchTimestampTest(unittest.TestCase):
    """Read only selected history while preserving IP membership and normalization."""

    def test_scope_avoids_unrelated_document_reads(self):
        history = {f"old{number}" for number in range(1000)}
        history.update({"match1", "match2"})
        indexer = make_indexer({"ip:8.8.8.8": history})
        indexer.r.hashes.update(
            {
                "doc:match1": {"first_seen": 100, "last_seen": 200},
                "doc:match2": {"first_seen": 150, "last_seen": 300},
            }
        )
        scope = ["match2", "match1", "match1", "not-in-ip"]
        result = indexer.get_timestamp_for_ip("8.8.8.8", scoped_uids=scope)
        self.assertEqual(
            result,
            {
                "match1": {"first_seen": 100, "last_seen": 200},
                "match2": {"first_seen": 150, "last_seen": 300},
                "min_seen": 100,
                "max_seen": 300,
            },
        )
        self.assertEqual(indexer.r.direct_reads, ["ip:8.8.8.8"])
        self.assertEqual(len(indexer.r.batches), 1)
        transaction, commands = indexer.r.batches[0]
        self.assertTrue(transaction)
        self.assertEqual(
            set(commands), {("hash", "doc:match1"), ("hash", "doc:match2")}
        )
        self.assertEqual(len(commands), 2)
        self.assertEqual(scope, ["match2", "match1", "match1", "not-in-ip"])
        self.assertEqual(indexer.r.sets["ip:8.8.8.8"], history)

    def test_no_scope_keeps_full_history_and_empty_scope_does_not_fall_back(self):
        indexer = make_indexer({"ip:8.8.8.8": {"old", "recent"}})
        indexer.r.hashes.update(
            {
                "doc:old": {"first_seen": 10, "last_seen": 100},
                "doc:recent": {"first_seen": 200, "last_seen": 300},
            }
        )
        full = {
            "old": {"first_seen": 10, "last_seen": 100},
            "recent": {"first_seen": 200, "last_seen": 300},
            "min_seen": 10,
            "max_seen": 300,
        }
        self.assertEqual(indexer.get_timestamp_for_ip("8.8.8.8"), full)
        self.assertEqual(indexer.get_timestamp_for_ip("8.8.8.8", None), full)
        for scope in ([], set(), {"not-in-ip"}):
            with self.subTest(scope=scope):
                self.assertEqual(
                    indexer.get_timestamp_for_ip("8.8.8.8", scope),
                    {"min_seen": None, "max_seen": None},
                )
                self.assertEqual(indexer.r.batches[-1], (True, []))
        self.assertEqual(
            indexer.get_timestamp_for_ip("missing-ip", {"recent"}),
            {"min_seen": None, "max_seen": None},
        )

    def test_missing_and_malformed_metadata_keep_normalized_timestamp_values(self):
        cases = {
            "missing": ({}, None, None),
            "invalid": ({"first_seen": "invalid", "last_seen": -1}, None, None),
            "first": ({"first_seen": "100"}, 100, 100),
            "last": ({"last_seen": "200"}, 200, 200),
            "reversed": ({"first_seen": 300, "last_seen": 100}, 100, 300),
            "formats": (
                {"first_seen": "2026-01-01T00:00:00Z", "last_seen": 1767225601000},
                1767225600,
                1767225601,
            ),
        }
        indexer = make_indexer({"ip:8.8.8.8": set(cases)})
        indexer.r.hashes = {
            f"doc:{uid}": data for uid, (data, _, _) in cases.items() if data
        }
        for uid, (_, first, last) in cases.items():
            with self.subTest(uid=uid):
                self.assertEqual(
                    indexer.get_timestamp_for_ip("8.8.8.8", {uid}),
                    {
                        uid: {"first_seen": first, "last_seen": last},
                        "min_seen": first,
                        "max_seen": last,
                    },
                )


def isolated_search_view(indexer):
    """Load actual pure view methods without booting Flask, DBs or scheduler."""
    tree = ast.parse((ROOT / "webapp/app/views.py").read_text())
    view = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "KVSearchView"
    )
    names = {
        "split_query_groups",
        "parse_query_group",
        "_parse_query_group_with_not",
        "parse_query",
        "_parse_http_headval_term",
        "_get_matching_uids",
        "execute_search",
        "execute_search_page",
        "_build_timestamp_array",
        "_build_requested_hostname_array",
    }
    view.bases = []
    view.decorator_list = []
    view.body = [
        node
        for node in view.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
    namespace = {
        "time": time,
        "shlex": shlex,
        "profile_search_page": profile_search_page,
        "logger": logging.getLogger(__name__),
        "KVrocksIndexer": lambda *_args: indexer,
        "db": SimpleNamespace(
            app=SimpleNamespace(config={"KVROCKS_HOST": "unused", "KVROCKS_PORT": 0})
        ),
        "lowercase_dict": lambda data: {
            key.lower(): [value.lower() for value in values]
            for key, values in data.items()
        },
        "is_valid_http_header_name": lambda name: bool(
            re.fullmatch(r"[a-z0-9-]+", name)
        ),
    }
    namespace["KVrocksIndexer"].normalize_timestamp = KVrocksIndexer.normalize_timestamp
    # Execute only selected repository methods, avoiding application startup.
    # pylint: disable=exec-used
    exec(
        compile(module, "<isolated KVSearchView>", "exec"), namespace
    )  # pylint: disable=exec-used
    result = namespace["KVSearchView"]()
    result.SINCE_PREFIX = "since:"
    result.SEARCH_PAGE_LIMIT = 100
    result.SEARCH_WINDOW_SECONDS = 86400
    result._resolve_time_range = lambda start, end, **_kwargs: (
        {"from_ts": start, "to_ts": end},
        True,
        None,
    )
    return result


class SearchConsumerTest(unittest.TestCase):
    """Real view execution, real indexer, in-memory backend with explicit UID sets."""

    def setUp(self):
        self.indexer = make_indexer()
        self.view = isolated_search_view(self.indexer)
        self.add_doc("u1", "8.8.8.8", 100, 200, "nginx", "443")
        self.add_doc("u2", "8.8.8.8", 100, 200, "apache", "80")
        self.add_doc("u3", "9.9.9.9", 200, 300, "apache", "443")
        self.add_doc("span", "1.1.1.1", 50, 350, "nginx", "443")

    def add_doc(
        self, uid, ip, first, last, server, port
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        client = self.indexer.r
        for key in (f"ip:{ip}", f"http_server:{server}", f"port:{port}", "all_uids"):
            client.sets.setdefault(key, set()).add(uid)
        client.sets.setdefault("all_ips", set()).add(ip)
        client.strings[f"uid:{uid}"] = ip
        client.hashes[f"doc:{uid}"] = {"ip": ip, "first_seen": first, "last_seen": last}
        client.sorted_sets.setdefault("first_seen_index", {})[uid] = first
        client.sorted_sets.setdefault("last_seen_index", {})[uid] = last

    def test_or_and_case_normalization_and_same_ip_separation(self):
        full = self.view.execute_search(
            "http_server.bg:NGINX OR http_server.lk:apache port:443", 200, 300
        )
        self.assertTrue(full["status"])
        self.assertEqual(
            {uid for uids in full["results"].values() for uid in uids},
            {"u1", "u3", "span"},
        )
        self.assertEqual(
            self.view.execute_search("http_server.bg:nginx port:80", 200, 300)[
                "results"
            ],
            {},
        )

    def test_overlap_export_path_and_last_seen_page_remain_distinct(self):
        full = self.view.execute_search("http_server.lk:n", 200, 300)
        page = self.view.execute_search_page("http_server.lk:n", 200, 300)
        self.assertEqual(set(full["results"]), {"8.8.8.8", "1.1.1.1"})
        self.assertEqual(page["results"], {"8.8.8.8": ["u1"]})
        self.assertEqual(page["timestamps"]["8.8.8.8"]["max_seen"], 200)

    def test_adjacent_windows_and_repeated_ip(self):
        self.add_doc("recent", "8.8.8.8", 86402, 86402, "nginx", "443")
        self.add_doc("boundary", "4.4.4.4", 86400, 86400, "nginx", "443")
        self.add_doc("next", "5.5.5.5", 86399, 86399, "nginx", "443")
        first = self.view.execute_search_page("http_server.bg:nginx", 0, 172799)
        self.assertEqual(set(first["results"]), {"8.8.8.8", "4.4.4.4"})
        self.assertEqual(first["pagination"]["next_cursor"], 86399)
        second = self.view.execute_search_page(
            "http_server.bg:nginx",
            0,
            172799,
            cursor_ts=86399,
            seen_ips=set(first["results"]),
        )
        self.assertEqual(set(second["results"]), {"5.5.5.5", "1.1.1.1"})
        self.assertFalse(second["pagination"]["has_more"])

    def test_over_100_ips_continue_same_window_and_full_export_set(self):
        for number in range(105):
            self.add_doc(
                f"extra{number}", f"10.0.0.{number + 1}", 200, 250, "nginx", "443"
            )
        full = self.view.execute_search("http_server.bg:nginx", 200, 300)
        first = self.view.execute_search_page("http_server.bg:nginx", 200, 300)
        self.assertEqual(len(full["results"]), 107)
        self.assertEqual(len(first["results"]), 100)
        self.assertTrue(first["pagination"]["stopped_in_window"])
        self.assertEqual(first["pagination"]["next_cursor"], 300)
        second = self.view.execute_search_page(
            "http_server.bg:nginx",
            200,
            300,
            cursor_ts=300,
            seen_ips=set(first["results"]),
        )
        self.assertEqual(len(second["results"]), 6)
        self.assertFalse(set(first["results"]) & set(second["results"]))
        self.assertEqual(second["pagination"]["next_cursor"], 199)
        self.assertFalse(second["pagination"]["has_more"])

    def test_debug_preserves_pages_exports_and_transport(self):
        query = 'http_server.lk:"nginx" OR http_server:apache port:443'
        for method in (self.view.execute_search_page, self.view.execute_search):
            for kwargs in ({}, {"cursor_ts": 300, "seen_ips": {"9.9.9.9"}, "limit": 1}):
                if method == self.view.execute_search and kwargs:
                    continue
                with self.subTest(method=method.__name__, kwargs=kwargs):
                    plain = method(query, 200, 300, **kwargs)
                    self.indexer.r.direct_reads.clear()
                    self.indexer.r.scans.clear()
                    self.indexer.r.batches.clear()
                    measured = method("debug " + query, 200, 300, **kwargs)
                    measured_transport = copy.deepcopy(
                        (
                            self.indexer.r.direct_reads,
                            self.indexer.r.scans,
                            self.indexer.r.batches,
                        )
                    )
                    self.indexer.r.direct_reads.clear()
                    self.indexer.r.scans.clear()
                    self.indexer.r.batches.clear()
                    method(query, 200, 300, **kwargs)
                    self.assertEqual(
                        measured_transport,
                        (
                            self.indexer.r.direct_reads,
                            self.indexer.r.scans,
                            self.indexer.r.batches,
                        ),
                    )
                    self.assertNotIn("debug", plain)
                    measured.pop("debug", None)
                    measured.pop("processingTimeMs")
                    plain.pop("processingTimeMs")
                    self.assertEqual(measured, plain)
                    self.assertNotIn("execute_command", vars(self.indexer.r))
                    self.assertNotIn("pipeline", vars(self.indexer.r))

    def test_scoped_history_preserves_previous_full_and_paged_responses(self):
        # Many tied IPs force limit+1 continuation. Unrelated, newer history must
        # not change sorting; spanning intervals still differ between page/export.
        for number in range(105):
            ip = f"10.0.0.{number + 1}"
            self.add_doc(f"extra{number}", ip, 200, 250, "nginx", "443")
            self.add_doc(f"history{number}", ip, 1, 900, "apache", "80")
        # Incomplete indexes: preserve omission from timestamps without changing
        # matching UID results, and preserve null timestamps for missing docs.
        self.indexer.r.sets["ip:8.8.8.8"].remove("u1")
        del self.indexer.r.hashes["doc:u3"]
        self.indexer.r.hashes["doc:extra0"] = {"first_seen": "invalid"}
        full_history = self.indexer.get_timestamp_for_ip
        query = "http_server.bg:nginx OR http_server:apache port:443"

        for method in (self.view.execute_search, self.view.execute_search_page):
            seen = set()
            for _ in range(2 if method == self.view.execute_search_page else 1):
                kwargs = (
                    {"cursor_ts": 300, "seen_ips": seen}
                    if method == self.view.execute_search_page
                    else {}
                )
                with patch.object(
                    self.indexer,
                    "get_timestamp_for_ip",
                    side_effect=lambda ip, **_kwargs: full_history(ip),
                ):
                    # The old path reads all metadata and filters in the view.
                    previous = method(query, 200, 300, **kwargs)
                current = method(query, 200, 300, **kwargs)
                previous.pop("processingTimeMs")
                current.pop("processingTimeMs")
                self.assertEqual(current, previous)
                # Dict equality ignores key order; check the visible IP order too.
                self.assertEqual(list(current["results"]), list(previous["results"]))
                seen.update(current["results"])
        self.assertFalse(current["pagination"]["has_more"])

    def test_debug_continuation_beyond_100_ips(self):
        for number in range(105):
            self.add_doc(
                f"extra{number}", f"10.0.0.{number + 1}", 200, 250, "nginx", "443"
            )
        seen = set()
        for expected_size in (100, 6):
            plain = self.view.execute_search_page(
                "http_server.bg:nginx", 200, 300, cursor_ts=300, seen_ips=seen
            )
            measured = self.view.execute_search_page(
                "debug http_server.bg:nginx", 200, 300, cursor_ts=300, seen_ips=seen
            )
            self.assertEqual(len(measured["results"]), expected_size)
            self.assertEqual(plain["results"], measured["results"])
            self.assertEqual(plain["pagination"], measured["pagination"])
            self.assertEqual(measured["debug"]["counts"]["returned_ips"], expected_size)
            seen.update(measured["results"])

    def test_debug_counts_full_sets_but_only_matching_ip_metadata(self):
        data = self.view.execute_search_page("http_server.lk:nginx debug", 200, 300)
        diagnostics = data["debug"]
        self.assertEqual(diagnostics["window"], {"from_ts": 200, "to_ts": 300})
        self.assertEqual(diagnostics["counts"]["window_uids"], 3)
        self.assertEqual(diagnostics["counts"]["matched_uids"], 1)
        self.assertEqual(diagnostics["counts"]["candidate_ips"], 1)
        self.assertEqual(diagnostics["counts"]["returned_ips"], 1)
        commands = diagnostics["kvrocks"]["commands"]
        self.assertEqual(commands["SCAN"]["reply_items"], 2)
        self.assertEqual(commands["SCAN"]["direct_calls"], 1)
        self.assertEqual(commands["SMEMBERS"]["direct_calls"], 2)
        # Full nginx/IP sets still read; only the matching history document fetched.
        self.assertEqual(commands["SMEMBERS"]["max_reply_items"], 2)
        self.assertEqual(commands["HGETALL"]["pipeline_calls"], 1)
        self.assertEqual(commands["GET"]["pipeline_calls"], 1)
        self.assertEqual(commands["SCARD"]["direct_calls"], 2)
        self.assertGreaterEqual(
            diagnostics["total_ms"], sum(diagnostics["stages_ms"].values())
        )
        self.assertIn("ip_history_timestamps", diagnostics["stages_ms"])
        # Diagnostics contain aggregates, never keys, IPs, UIDs or field values.
        for private in ("8.8.8.8", "nginx", "u1", "http_server:"):
            self.assertNotIn(private, str(diagnostics))

    def test_debug_directive_and_invalid_queries(self):
        for query in ("debug", "since:1 debug", "debug OR port:443", 'debug port:"443'):
            self.assertFalse(self.view.execute_search_page(query, 200, 300)["status"])
        self.assertFalse(self.view.parse_query("debug port:443")[1])
        self.assertTrue(self.view.parse_query("http_title:debug")[1])
        self.assertFalse(debug_requested('http_title:"some debug text"'))
        self.assertTrue(debug_requested("port:443 DEBUG since:1"))
        parsed = self.view.parse_query(
            'DEBUG http_title:"some debug text" since:1',
            allow_since_directive=True,
            allow_debug_directive=True,
        )
        self.assertEqual(parsed[0], [{"http_title": ["some debug text"]}])
        empty = self.view.execute_search_page("debug port:999", 200, 300)
        self.assertTrue(empty["status"])
        self.assertEqual(empty["debug"]["counts"]["returned_ips"], 0)

    def test_debug_restores_client_after_backend_failure(self):
        def fail(*_args, **_kwargs):
            raise RuntimeError("backend unavailable")

        self.indexer.r.execute_command = fail
        with self.assertRaisesRegex(RuntimeError, "backend unavailable"):
            self.view.execute_search_page("debug port:443", 200, 300)
        self.assertIs(self.indexer.r.execute_command, fail)
        self.assertNotIn("pipeline", vars(self.indexer.r))


if __name__ == "__main__":
    unittest.main()
