"""Protocol evidence from stored reports must survive indexing and retagging."""

from pathlib import Path
from unittest import TestCase

import yaml
from app.utils.index_reconciliation import FIELDS
from app.utils.result_parser import parse_json, prepare_kvrocks_document
from app.utils.tag_reconciliation import RulePlan
from app.utils.tagrules import compile_tag_rule_definition


class SavedReportTests(TestCase):
    """Regression checks for saved report tests."""

    @classmethod
    def setUpClass(cls):
        """Load shared fixtures without starting external workers."""
        directory = Path(__file__).resolve().parents[1] / "webapp/tags/tags"
        cls.rules = []
        definitions = {}
        for name in (
            "ssh",
            "openssh",
            "smtp",
            "http",
            "tls",
            "rdp",
            "ftp_welcome",
            "pure_ftpd",
        ):
            rule = yaml.safe_load((directory / f"{name}.yaml").read_bytes())
            cls.rules.append(
                compile_tag_rule_definition(
                    rule["name"], rule["description"], rule["query"], rule["tags"]
                )
            )
            definitions[rule["uuid"]] = {"query": rule["query"], "tags": rule["tags"]}
        cls.plan = RulePlan(
            {
                "rules": definitions,
                "parser": {
                    "HTTP_HEADER_COLLECTION": {
                        "cache-control": True,
                        "content-type": True,
                    }
                },
                "code": "fixture",
            }
        )

    def check_tags(self, port, expected):
        # A synthetic stored document; the parser expects a routable address.
        """Provide the check tags test fixture."""
        raw = {
            "id": "saved-report",
            "ip": "93.184.216.34",
            "body": {"endtime": "100", "ports": [port]},
        }
        parsed = parse_json(raw, {}, tag_rules=self.rules)
        indexed = prepare_kvrocks_document(raw, parsed, tag_rules=self.rules)
        self.assertEqual(sorted(parsed.get("tag", [])), sorted(expected))
        self.assertEqual(sorted(indexed.get("tag", [])), sorted(expected))
        # Model the fields restored from Kvrocks before incremental retagging.
        restored = {key: indexed[key] for key in FIELDS if key in indexed}
        retagged, _ = self.plan.evaluate(restored, force=True)
        self.assertEqual(retagged, sorted(expected))
        return indexed

    def test_port_number_and_service_table_are_not_evidence(self):
        """Verify port number and service table are not evidence."""
        for service in ({}, {"method": "table", "name": "ssh"}):
            self.check_tags({"portid": "22", "service": service}, [])
        self.check_tags(
            {"portid": "2222", "service": {"method": "probed", "name": "ssh"}},
            ["proto:ssh"],
        )

    def test_ssh_with_and_without_banner(self):
        """Verify ssh with and without banner."""
        detection = {"id": "masscan-detection", "service": "ssh"}
        port = {"portid": "2222", "scripts": [detection]}
        self.check_tags(port, ["proto:ssh"])
        detection["output"] = "SSH-2.0-OpenSSH_9.6"
        doc = self.check_tags(port, ["proto:ssh", "product:openssh", "vendor:openssh"])
        self.assertEqual(doc["banner"], [detection["output"]])

    def test_rdp_requires_service_evidence(self):
        """Verify rdp requires service evidence."""
        self.check_tags({"portid": "3389"}, [])
        self.check_tags(
            {"portid": "3389", "service": {"name": "rdp", "method": "table"}}, []
        )
        detection = {"id": "masscan-detection", "service": "rdp"}
        self.check_tags({"portid": "3390", "scripts": [detection]}, ["proto:rdp"])

    def test_ftp_protocol_requires_observed_evidence(self):
        """Verify ftp protocol requires observed evidence."""
        self.check_tags({"portid": "21"}, [])
        self.check_tags(
            {"portid": "21", "service": {"name": "ftp", "method": "table"}}, []
        )
        self.check_tags(
            {
                "portid": "2121",
                "scripts": [{"id": "masscan-detection", "service": "ftp"}],
            },
            ["proto:ftp"],
        )

    def test_pure_ftpd_standard_and_short_greetings_match_both_scanners(self):
        """Verify pure ftpd standard and short greetings match both scanners."""
        expected = ["proto:ftp", "product:pure-ftpd", "vendor:pure"]
        for prefix in (
            "220---------- Welcome to Pure-FTPd [TLS] ----------",
            "220-Welcome to Pure-FTPd.",
        ):
            for separator in (r"\x0D\x0A", r"\x0A"):
                output = prefix + separator + "220-You are user number 1 of 10 allowed."
                for script_id in ("banner", "masscan-detection"):
                    script = {"id": script_id, "output": output}
                    if script_id == "masscan-detection":
                        script["service"] = "ftp"
                    self.check_tags({"portid": "2121", "scripts": [script]}, expected)
        self.check_tags(
            {
                "portid": "21",
                "scripts": [
                    {"id": "banner", "output": "220-Welcome to another FTP server."}
                ],
            },
            [],
        )

    def test_starttls_and_direct_tls(self):
        """Verify starttls and direct tls."""
        smtp = {
            "id": "masscan-detection",
            "service": "smtp",
            "output": "220 ESMTP STARTTLS",
        }
        tls = {"id": "masscan-detection", "service": "ssl", "output": " ALERT(0x0246) "}
        self.check_tags({"portid": "25", "scripts": [smtp]}, ["proto:smtp"])
        doc = self.check_tags(
            {"portid": "25", "scripts": [smtp, tls]}, ["proto:smtp", "proto:tls"]
        )
        self.assertEqual(doc["service"], ["smtp", "ssl"])
        self.check_tags({"portid": "443", "scripts": [tls]}, ["proto:tls"])
