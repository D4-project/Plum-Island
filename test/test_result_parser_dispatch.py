"""Regression tests for parser dispatch and incomplete historical scan documents."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp/app/utils"))
import result_parser as parser  # pylint: disable=wrong-import-position,import-error


class ParserDispatchTest(unittest.TestCase):
    """Exercise parsing and the subsequent Kvrocks preparation step."""

    def test_absent_or_null_scan_data(self):
        """Incomplete scans carry identity through both stages without a TLS tag."""
        for extra in ({}, {"body": None}, {"body": {}}, {"body": {"ports": None}}):
            with self.subTest(extra=extra):
                doc = {"id": "example", "ip": "8.8.8.8", **extra}
                parsed = parser.parse_json(doc, {}, tag_rules=[])
                indexed = parser.prepare_kvrocks_document(doc, parsed, tag_rules=[])
                for result in (parsed, indexed):
                    self.assertEqual(result["uid"], "example")
                    self.assertEqual(result["port"], [])
                    self.assertIsNone(result["last_seen"])
                    self.assertNotIn("proto:tls", result.get("tag", []))
                self.assertEqual(indexed["port_protocol"], [])

    def test_dispatch_covers_default_profile(self):
        """Every active extraction action has a registered callable."""
        for rule in parser.default_parsing:
            action = rule.split(":", 1)[0]
            self.assertTrue(callable(parser._PARSER_DISPATCH[action]))

    def test_hash_is_not_an_extraction_action(self):
        """Reject hsh even if the document has no matching script."""
        with patch.object(parser, "default_parsing", ["hsh:p.http-headers.output"]):
            with self.assertRaisesRegex(TypeError, "Action 'hsh' is not supported"):
                parser.parse_json({"ip": "8.8.8.8", "body": {}}, {}, tag_rules=[])
