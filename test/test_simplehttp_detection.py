#!/usr/bin/env python3
"""Regression coverage for SimpleHTTP server detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


SIMPLEHTTP_GROUPS = [{"http_server.bg": ["SimpleHTTP"]}]


class SimpleHttpDetectionTest(TestCase):
    """Verify SimpleHTTP receives the Python language tag."""

    def test_simplehttp_server_matches(self):
        self.assertTrue(
            document_matches_criteria_groups(
                {"http_server": ["SimpleHTTP/0.6 Python/3.12.3"]},
                SIMPLEHTTP_GROUPS,
            )
        )

    def test_unrelated_server_does_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["Apache/2.4.25"]}, SIMPLEHTTP_GROUPS
            )
        )

    def test_yaml_rule_contains_simplehttp_signal(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/simplehttp.yaml").read_text())
        self.assertEqual(rule["description"], "SimpleHTTP")
        self.assertEqual(rule["query"], 'http_server.bg:"SimpleHTTP"')
        self.assertEqual(
            rule["tags"],
            ["product:simplehttp", "type:web-server", "lang:python", "vendor:python"],
        )


if __name__ == "__main__":
    main()
