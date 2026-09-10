#!/usr/bin/env python3
"""Regression coverage for Python SimpleHTTP server detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


PYTHON_GROUPS = [{"http_server.bg": ["SimpleHTTP"]}]


class PythonDetectionTest(TestCase):
    """Verify SimpleHTTP receives the Python language tag rule."""

    def test_simplehttp_server_matches(self):
        self.assertTrue(
            document_matches_criteria_groups(
                {"http_server": ["SimpleHTTP/0.6 Python/3.12.3"]}, PYTHON_GROUPS
            )
        )

    def test_unrelated_server_does_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["Apache/2.4.25"]}, PYTHON_GROUPS
            )
        )

    def test_yaml_rule_contains_simplehttp_signal(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/python.yaml").read_text())
        self.assertIn('http_server.bg:"SimpleHTTP"', rule["query"])
        self.assertEqual(rule["tags"], ["lang:python"])


if __name__ == "__main__":
    main()
