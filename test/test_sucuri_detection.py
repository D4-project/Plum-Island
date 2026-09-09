#!/usr/bin/env python3
"""Regression coverage for Sucuri Website Firewall detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


SUCURI_GROUPS = [
    {"http_server.lk": ["Sucuri/Cloudproxy"]},
    {"http_header": ["x-sucuri-id"]},
    {"http_header": ["x-sucuri-block"]},
    {"http_title.lk": ["Sucuri WebSite Firewall - Access Denied"]},
]


class SucuriDetectionTest(TestCase):
    """Verify Sucuri firewall response indicators are detected."""

    def test_each_signal_matches(self):
        documents = (
            {"http_server": ["Sucuri/Cloudproxy"]},
            {"http_header": ["x-sucuri-id"]},
            {"http_header": ["x-sucuri-block"]},
            {"http_title": ["Sucuri WebSite Firewall - Access Denied"]},
        )
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, SUCURI_GROUPS))

    def test_other_servers_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["nginx/1.27.0"]}, SUCURI_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/sucuri.yaml").read_text())
        self.assertIn("http_header:x-sucuri-id", rule["query"])
        self.assertEqual(
            rule["tags"], ["product:sucuri-firewall", "vendor:sucuri", "type:firewall"]
        )


if __name__ == "__main__":
    main()
