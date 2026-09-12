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

# pylint: disable=missing-function-docstring,protected-access

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webapp/app/utils"))
from kvrocks import KVrocksIndexer  # pylint: disable=wrong-import-position


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
        self.direct_reads.append(key)
        return set(self.sets.get(key, set()))

    def scard(self, key):
        return len(self.sets.get(key, set()))

    def zrangebyscore(self, key, minimum, maximum):
        return {
            uid
            for uid, score in self.sorted_sets.get(key, {}).items()
            if float(minimum) <= score <= float(maximum)
        }

    def scan_iter(self, match, count=None):
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
        yield from (key for key in keys if re.fullmatch(pattern, key))


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


if __name__ == "__main__":
    unittest.main()
