#!/usr/bin/env python3
"""Regression coverage for Lighttpd server detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


LIGHTTPD_GROUPS = [{"http_server.lk": ["lighttpd"]}]


class LighttpdDetectionTest(TestCase):
    """Verify Lighttpd server banners are detected without false positives."""

    def test_lighttpd_server_versions_match(self):
        for value in ("lighttpd/1.4.82", "lighttpd/1.4.76", "LIGHTTPD/1.4.82"):
            self.assertTrue(
                document_matches_criteria_groups(
                    {"http_server": [value]}, LIGHTTPD_GROUPS
                )
            )

    def test_other_servers_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["nginx/1.27.0"]}, LIGHTTPD_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/lighttpd.yaml").read_text())
        self.assertEqual(rule["query"], "http_server.lk:lighttpd")
        self.assertEqual(
            rule["tags"], ["product:lighttpd", "vendor:lighttpd"]
        )


if __name__ == "__main__":
    main()
