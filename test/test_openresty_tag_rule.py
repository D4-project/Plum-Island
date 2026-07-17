#!/usr/bin/env python3
"""
Tests for OpenResty tag-rule coverage.
"""

import unittest
from pathlib import Path

import yaml

REPO_DIR = Path(__file__).resolve().parent.parent


class OpenRestyTagRuleTest(unittest.TestCase):
    """
    Verify OpenResty detection covers Server header values.
    """

    def test_openresty_server_header_is_detected(self):
        """OpenResty rule must match Server header values."""
        rule_path = REPO_DIR / "webapp" / "tags" / "openresty.yaml"
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

        self.assertIn("http_server.bg:openresty", payload["query"])
        self.assertIn("product:openresty", payload["tags"])
        self.assertIn("vendor:openresty", payload["tags"])


if __name__ == "__main__":
    unittest.main()
