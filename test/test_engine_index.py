"""Sparse scanner provenance: legacy and unmarked reports are always Nmap."""

from copy import deepcopy
from test.test_kvrocks_search import isolated_search_view, make_indexer
from test.test_reimport_history import KVrocksIndexer, MemoryStore
from unittest import TestCase
from unittest.mock import Mock

from app.utils.index_reconciliation import FIELDS
from app.utils.result_parser import parse_json, prepare_kvrocks_document
from search_plan import CandidatePlanner


class EngineIndexTest(TestCase):
    """Regression checks for engine index test."""

    def raw(self, engine=None):
        """Provide the raw test fixture."""
        result = {
            "id": "one",
            "ip": "8.8.8.8",
            "body": {"endtime": "100", "ports": [{"portid": "443", "protocol": "tcp"}]},
        }
        if engine is not None:
            result["body"]["engine"] = engine
        return result

    def test_legacy_default_and_explicit_provenance(self):
        """Verify legacy default and explicit provenance."""
        for engine, expected in (
            (None, "nmap"),
            ("nmap", "nmap"),
            ("masscan", "masscan"),
            (" MASSCAN ", "masscan"),
        ):
            raw = self.raw(engine)
            before = deepcopy(raw)
            parsed = parse_json(raw, {})
            self.assertEqual(parsed["engine"], [expected])
            self.assertEqual(
                prepare_kvrocks_document(raw, parsed)["engine"], [expected]
            )
            self.assertEqual(raw, before)
        self.assertIn("engine", FIELDS)

    def test_old_indexes_work_immediately_without_any_writes(self):
        """Verify old indexes work immediately without any writes."""
        indexer = make_indexer(
            {
                "all_uids": {"old", "new", "masscan"},
                "engine:masscan": {"masscan"},
                "port:443": {"old", "masscan"},
            }
        )
        view = isolated_search_view(indexer)
        cases = {
            "engine:nmap": {"old", "new"},
            "engine:masscan": {"masscan"},
            "port:443 engine:nmap": {"old"},
            "engine:nmap port:443": {"old"},
            "engine:masscan AND NOT engine:nmap": {"masscan"},
            "engine:nmap OR engine:masscan": {"old", "new", "masscan"},
            "engine:nmap engine:masscan": set(),
            "port:443 AND NOT engine:masscan": {"old"},
            "port:443 AND NOT engine:nmap": {"masscan"},
        }
        before = deepcopy(indexer.r.sets)
        for query, expected in cases.items():
            compiled, valid, message = view.parse_query(query)
            self.assertTrue(valid, message)
            self.assertEqual(
                CandidatePlanner(indexer, compiled).execute(), expected, query
            )
            self.assertEqual(
                CandidatePlanner(indexer, compiled, scope={"old"}).execute(),
                expected & {"old"},
                query,
            )
        self.assertEqual(indexer.r.sets, before)
        self.assertFalse(view.parse_query("engine.lk:masscan")[1])
        self.assertFalse(view.parse_query("tool:masscan")[1])

    def test_new_writes_only_store_masscan_membership(self):
        """Verify new writes only store masscan membership."""
        store = MemoryStore()
        store.scard = lambda key: len(store.smembers(key))
        indexer = KVrocksIndexer.__new__(KVrocksIndexer)
        indexer.r = store
        store.delete = Mock(wraps=store.delete)
        indexer.add_documents_batch([{"uid": "one", "ip": "8.8.8.8"}])
        self.assertNotIn("engine:nmap", store.data)
        self.assertNotIn("engines:one", store.data)
        self.assertFalse(
            any("engines:one" in call.args for call in store.delete.call_args_list)
        )
        indexer.add_documents_batch(
            [{"uid": "one", "ip": "8.8.8.8", "engine": ["masscan"]}]
        )
        self.assertEqual(store.smembers("engine:masscan"), {"one"})
        self.assertEqual(store.smembers("engines:one"), {"masscan"})
        indexer.add_documents_batch([{"uid": "one", "ip": "8.8.8.8"}])
        self.assertEqual(store.smembers("engine:masscan"), set())
        self.assertNotIn("engine:nmap", store.data)

    def test_narrow_query_does_not_read_all_uids(self):
        """Verify narrow query does not read all uids."""
        indexer = make_indexer(
            {
                "all_uids": {"old", "masscan", "other"},
                "engine:masscan": {"masscan"},
                "port:443": {"old", "masscan"},
            }
        )
        original = indexer.r.smembers

        def read(key):
            """Provide the read test fixture."""
            self.assertNotEqual(key, "all_uids")
            return original(key)

        indexer.r.smembers = Mock(side_effect=read)
        view = isolated_search_view(indexer)
        query, _, _ = view.parse_query("engine:nmap port:443")
        self.assertEqual(CandidatePlanner(indexer, query).execute(), {"old"})
        self.assertEqual(
            set(indexer.get_uids_by_criteria({"engine": ["nmap"], "port": ["443"]})),
            {"old"},
        )
        self.assertEqual(
            set(
                indexer.get_uids_by_criteria_scoped(
                    {"engine": ["nmap"]}, {"old", "masscan"}
                )
            ),
            {"old"},
        )
