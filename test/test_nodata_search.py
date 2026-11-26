"""Exercise exact open-only searches over the normal capture index."""

from test.test_kvrocks_search import isolated_search_view
from test.test_reimport_history import MemoryStore
from unittest import TestCase

from app.utils.index_reconciliation import index_for, parsed_source


class NoDataSearchTest(TestCase):
    """Keep application evidence and per-port matches distinct."""

    def setUp(self):
        store = MemoryStore()
        store.scard = lambda key: len(store.smembers(key))
        store.sismember = lambda key, uid: uid in store.smembers(key)
        self.indexer = index_for(store)
        self.view = isolated_search_view(self.indexer)

    def index_capture(self, uid, ports, engine=None):
        source = {
            "id": uid,
            "ip": "93.184.216.34",
            "body": {
                "starttime": "100",
                "endtime": "101",
                "hostnames": [{"name": "www.example.test", "type": "user"}],
                "ports": ports,
            },
        }
        if engine:
            source["body"]["engine"] = engine
        parsed = parsed_source(source, {"parser": {}})
        self.indexer.add_documents_batch([parsed])

    def assert_matches(self, query, expected):
        criteria, valid, message = self.view.parse_query(query)
        self.assertTrue(valid, message)
        self.assertEqual(
            self.view._get_matching_uids(self.indexer, criteria), expected, query
        )

    def test_open_only_with_hostnames_and_zero_ttl(self):
        """Find a plain open TCP 30 observation with its existing metadata."""
        plain = {
            "protocol": "tcp",
            "portid": "30",
            "state": {"state": "open", "reason_ttl": "0"},
            "service": {"name": "unknown", "method": "table"},
        }
        self.index_capture("plain", [plain], "masscan")
        self.index_capture("closed", [dict(plain, state={"state": "closed"})])
        self.index_capture(
            "service",
            [dict(plain, service={"name": "ssh", "method": "probed"})],
        )
        self.index_capture(
            "response",
            [dict(plain, scripts=[{"id": "masscan-detection", "service": "ssl"}])],
            "masscan",
        )
        self.index_capture(
            "script", [dict(plain, scripts=[{"id": "ssl-cert", "output": "cert"}])]
        )

        for query in ("nodata", "nodata:30", "port:30 nodata", "engine:masscan nodata"):
            with self.subTest(query=query):
                self.assert_matches(query, {"plain"})
        for query in ("nodata:65536", "nodata:udp", "nodata.lk:30"):
            with self.subTest(query=query):
                self.assertFalse(self.view.parse_query(query)[1])

        self.index_capture(
            "plain", [dict(plain, scripts=[{"id": "banner", "output": "SSH-2.0"}])]
        )
        self.assert_matches("nodata", set())
        self.assertFalse(self.indexer.r.smembers("nodata:30"))

    def test_same_port_with_historical_multi_port_document(self):
        """A data-free port in a legacy record does not match another port."""
        self.index_capture(
            "legacy",
            [
                {"portid": "30", "protocol": "tcp", "state": {"state": "open"}},
                {
                    "portid": "443",
                    "protocol": "tcp",
                    "state": {"state": "open"},
                    "scripts": [{"id": "ssl-cert", "output": "cert"}],
                },
            ],
        )
        self.assert_matches("port:30 nodata", {"legacy"})
        self.assert_matches("nodata:30", {"legacy"})
        self.assert_matches("port:443 nodata", set())
        self.assert_matches("nodata:443", set())
