#!/usr/bin/env python3
"""
Tests for Wyse Management Suite tag-rule coverage.
"""

import unittest
from pathlib import Path

import yaml

REPO_DIR = Path(__file__).resolve().parent.parent


class WyseManagementSuiteTagRuleTest(unittest.TestCase):
    """
    Verify Wyse Management Suite detection covers title values.
    """

    def test_wyse_management_suite_title_is_detected(self):
        """Wyse Management Suite rule must match title values."""
        rule_path = REPO_DIR / "webapp" / "tags" / "wyse_management_suite.yaml"
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

        self.assertIn('http_title.bg:"Wyse Management Suite"', payload["query"])
        self.assertIn("vendor:dell", payload["tags"])
        self.assertIn("product:wyse-management-suite", payload["tags"])


if __name__ == "__main__":
    unittest.main()
