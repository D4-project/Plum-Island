"""Per-port proof for filtering, result labels and the IP view."""

import ipaddress
import json
import unittest
from unittest.mock import Mock, patch

from app.utils.filtered_scans import filtered_candidates, first_scan_candidate
from app.utils.scan_ports import build_scan_port
from app.utils.search_existence import plan_terms
from app.utils.search_plan import build_plan
from app.utils.tag_reconciliation import RulePlan
from app.views import KVSearchView

from test.test_kvrocks_search import make_indexer
from test.test_tag_reconciliation import snapshot


def capture(number, protocol="tcp", state="open"):
    """One observation with a transport and port state."""
    return {
        "ip": "8.8.8.8",
        "body": {
            "ports": [
                {
                    "portid": str(number),
                    "protocol": protocol,
                    "state": {"state": state, "reason_ttl": 52},
                }
            ]
        },
    }


class ScanPortEvidenceTest(unittest.TestCase):
    """Exercise provenance, identity and early validation without services."""

    def test_document_proof_excludes_host_tags_and_rejects_udp_and_closed(self):
        """Only a positive port-level rule can justify a TCP port."""
        plan = RulePlan(
            snapshot(
                [
                    ("web", "http_server:nginx", ["vendor:nginx"]),
                    ("host", "domain_requested:example.org", ["type:site"]),
                    ("stack", "tag:vendor:nginx", ["type:webserver"]),
                ]
            )
        )
        document = {
            "ip": "8.8.8.8",
            "http_server": ["nginx"],
            "domain_requested": ["example.org"],
        }
        result = build_scan_port(capture(443), document, plan)
        self.assertEqual(result["revision"], plan.snapshot["revision"])
        self.assertEqual(result["open_tcp_port"], 443)
        self.assertEqual(result["ttl"], 52)
        self.assertEqual(result["tags"], ["type:webserver", "vendor:nginx"])
        for protocol, state in (("udp", "open"), ("tcp", "closed")):
            with self.subTest(protocol=protocol, state=state):
                result = build_scan_port(capture(443, protocol, state), document, plan)
                self.assertIsNone(result["open_tcp_port"])
                self.assertEqual(result["tags"], [])

    def test_nse_proof_survives_unrelated_fast_retag(self):
        """Published NSE proof can survive without another source read."""
        rule = ("rdp", "nse.body:rdp.lk:detected", ["proto:rdp"])
        previous = snapshot([rule])
        source = capture(3389)
        source["body"]["ports"][0]["scripts"] = [{"id": "rdp", "output": "Detected"}]
        document = {"ip": "8.8.8.8"}
        summary = build_scan_port(source, document, RulePlan(previous))
        current = RulePlan(
            snapshot([rule, ("c", "http_server:nginx", ["proto:http"])]), previous
        )
        updated = build_scan_port(None, document, current, summary)
        self.assertEqual(updated["tags"], ["proto:rdp"])
        self.assertNotEqual(updated["revision"], summary["revision"])

    def test_nginx_only_labels_matching_port_on_shared_address(self):
        """SSH, host-only tags and closed ports cannot claim an nginx result."""
        ip = "8.8.8.8"
        candidates = {ip: ["ssh", "web", "host", "closed"]}
        indexer = make_indexer(
            {
                "tag:vendor:nginx": {"web", "host", "closed"},
                "tag:proto:ssh": {"ssh"},
                "fqdn_requested:example.org": {"host", "ssh"},
            }
        )
        for uid, port, tags in (
            ("web", 443, ["vendor:nginx"]),
            ("ssh", 22, ["proto:ssh"]),
            ("host", 8080, []),
            ("closed", None, ["vendor:nginx"]),
        ):
            indexer.r.strings[f"scan_port:{uid}"] = json.dumps(
                {"open_tcp_port": port, "tags": tags}
            )
        cases = {
            "tag:vendor:nginx": [443],
            "tag:vendor:nginx OR tag:proto:ssh": [22, 443],
            "(tag:vendor:nginx AND NOT fqdn_requested:example.org) OR tag:proto:ssh": [
                22,
                443,
            ],
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                criteria, valid, error = KVSearchView().parse_query(query)
                self.assertTrue(valid, error)
                self.assertEqual(
                    KVSearchView._matching_ports_by_ip(
                        indexer, criteria, candidates, set(candidates[ip])
                    ),
                    {ip: expected},
                )

    def test_covered_filter_preserves_configured_ip_and_requested_fqdn(self):
        """The first probe returns before another page or any Meili read."""
        uid, address, name = "covered", "8.8.8.8", "host.example.org"
        criteria, valid, error = KVSearchView().parse_query("tag:vendor:nginx")
        self.assertTrue(valid, error)
        plan = build_plan(criteria, scoped_membership=True, factor=False)
        hit = (
            uid,
            ipaddress.ip_address(address),
            dict.fromkeys(plan_terms(plan), True),
        )
        indexer = make_indexer({f"fqdn_requesteds:{uid}": {name}})
        indexer.r.strings[f"scan_port:{uid}"] = json.dumps(
            {"open_tcp_port": 443, "tags": ["vendor:nginx"]}
        )
        selection = {address: 7, name: 11}, [], []
        meili = Mock()

        def pages(*_args, **_kwargs):
            yield plan, [hit]
            raise AssertionError("The validation probe read another page")

        with patch("app.utils.filtered_scans.observation_batches", pages), patch(
            "app.utils.filtered_scans._selection_context",
            return_value=selection,
        ):
            self.assertEqual(
                first_scan_candidate(indexer, meili, criteria, 10, 20, {}),
                (11, "fqdn", name, {443}),
            )
        with patch(
            "app.utils.filtered_scans.observation_batches",
            return_value=iter([(plan, [hit])]),
        ):
            self.assertEqual(
                list(
                    filtered_candidates(
                        indexer,
                        meili,
                        criteria,
                        10,
                        20,
                        {},
                        selection=selection,
                    )
                ),
                [(11, "fqdn", name, {443}), (7, "ip", address, {443})],
            )
        meili.get_document.assert_not_called()

    def test_existing_nodata_index_distinguishes_tcp_and_udp(self):
        """Known nodata transports require no Meili fetch before backfill."""
        criteria, valid, error = KVSearchView().parse_query("nodata")
        self.assertTrue(valid, error)
        plan = build_plan(criteria, scoped_membership=True, factor=False)
        terms = dict.fromkeys(plan_terms(plan), True)
        address = ipaddress.ip_address("8.8.8.8")
        indexer = make_indexer(
            {
                "port_protocols:tcp": {"tcp/80"},
                "nodatas:tcp": {"true", "80"},
                "port_protocols:udp": {"udp/53"},
                "nodatas:udp": {"true", "53"},
            }
        )
        meili = Mock()
        with patch(
            "app.utils.filtered_scans.observation_batches",
            return_value=iter(
                [(plan, [("tcp", address, terms), ("udp", address, terms)])]
            ),
        ):
            result = list(
                filtered_candidates(
                    indexer,
                    meili,
                    criteria,
                    10,
                    20,
                    {},
                    selection=({"8.8.8.8": 7}, [], []),
                )
            )
        self.assertEqual(result, [(7, "ip", "8.8.8.8", {80})])
        meili.get_document.assert_not_called()
