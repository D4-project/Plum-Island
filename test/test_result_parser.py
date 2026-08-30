#!/usr/bin/env python3
"""
Unit tests for result_parser.parse_json — central data-flow function.
"""

import os
import sys
from unittest import TestCase, main

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.utils.result_parser import parse_json  # pylint: disable=wrong-import-position


def _minimal_body():
    return {
        "endtime": "1700000000",
        "hostnames": [],
        "ports": [
            {
                "portid": "80",
                "scripts": [
                    {"id": "http-headers", "output": "Server: nginx\r\n"},
                    {"id": "http-title", "output": "Welcome"},
                ],
            }
        ],
    }


class TestParseJson(TestCase):
    """Tests for parse_json correctness and null-safety."""

    def _parse(self, doc):
        return parse_json(doc, {})

    def test_minimal_document_populates_uid_ip_port(self):
        """A well-formed document produces uid, ip, and port in the result."""
        doc = {"id": "test-uid-abc", "ip": "1.2.3.4", "body": _minimal_body()}
        result = self._parse(doc)
        self.assertEqual(result["uid"], "test-uid-abc")
        self.assertEqual(result["ip"], "1.2.3.4")
        self.assertIn("80", result.get("port", []))

    def test_null_body_does_not_crash(self):
        """parse_json must not raise when body is None (regression for #145 fix)."""
        doc = {"id": "uid-null-body", "ip": "1.2.3.4", "body": None}
        try:
            self._parse(doc)
        except Exception as exc:
            self.fail(f"parse_json raised on None body: {exc}")

    def test_empty_body_does_not_crash(self):
        """parse_json must not raise when body is an empty dict."""
        doc = {"id": "uid-empty-body", "ip": "1.2.3.4", "body": {}}
        try:
            self._parse(doc)
        except Exception as exc:
            self.fail(f"parse_json raised on empty body: {exc}")

    def test_missing_body_key_does_not_crash(self):
        """parse_json must not raise when the body key is absent entirely."""
        doc = {"id": "uid-no-body", "ip": "1.2.3.4"}
        try:
            self._parse(doc)
        except Exception as exc:
            self.fail(f"parse_json raised on missing body key: {exc}")

    def test_empty_ports_list_does_not_crash(self):
        """parse_json must not raise when ports list is empty."""
        doc = {"id": "uid-no-ports", "ip": "1.2.3.4", "body": {"ports": [], "endtime": "0"}}
        try:
            result = self._parse(doc)
        except Exception as exc:
            self.fail(f"parse_json raised on empty ports: {exc}")
        self.assertEqual(result.get("port"), [])

    def test_result_contains_uid_and_ip(self):
        """uid and ip are always forwarded to the result."""
        doc = {"id": "my-uid", "ip": "10.20.30.40", "body": _minimal_body()}
        result = self._parse(doc)
        self.assertEqual(result["uid"], "my-uid")
        self.assertEqual(result["ip"], "10.20.30.40")


if __name__ == "__main__":
    main()
