#!/usr/bin/env python3
"""Regression coverage for ScreenConnect HTTP server detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from result_parser import parse_json  # pylint: disable=wrong-import-position
from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


SCREENCONNECT_GROUPS = [{"http_server.bg": ["screenconnect/"]}]


def parse_server(server):
    """Parse a minimal HTTP server response."""
    document = {
        "id": "screenconnect-detection",
        "ip": "93.184.216.34",
        "body": {
            "endtime": "2026-09-08T00:00:00",
            "hostnames": [],
            "ports": [
                {
                    "portid": "443",
                    "scripts": [
                        {
                            "id": "http-headers",
                            "output": f"HTTP/1.1 200 OK\r\nServer: {server}\r\n",
                        }
                    ],
                }
            ],
        },
    }
    return parse_json(
        document,
        {
            "ONLINETLD": False,
            "TLDS": [],
            "TLDADD": [],
            "HTTP_HEADER_COLLECTION": {},
        },
        tag_rules=[],
    )


class ScreenConnectDetectionTest(TestCase):
    """Verify prefix and case-insensitive matching for ScreenConnect."""

    def test_screenconnect_prefix_matches_case_insensitively(self):
        for server in ("ScreenConnect/23.9", "screenconnect/24.1-build"):
            self.assertTrue(
                document_matches_criteria_groups(
                    parse_server(server), SCREENCONNECT_GROUPS
                )
            )

    def test_embedded_or_unrelated_server_values_do_not_match(self):
        for server in ("Apache ScreenConnect/23.9", "nginx", "ScreenConnect"):
            self.assertFalse(
                document_matches_criteria_groups(
                    parse_server(server), SCREENCONNECT_GROUPS
                )
            )

    def test_yaml_rule_contains_expected_query_and_tag(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/screenconnect.yaml").read_text())
        self.assertEqual(rule["query"], "http_server.bg:screenconnect/")
        self.assertEqual(rule["tags"], ["product:screenconnect"])


if __name__ == "__main__":
    main()
