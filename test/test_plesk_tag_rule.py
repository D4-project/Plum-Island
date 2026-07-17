#!/usr/bin/env python3
"""
Tests for Plesk tag-rule coverage.
"""

import unittest
from pathlib import Path

import yaml

REPO_DIR = Path(__file__).resolve().parent.parent


class PleskTagRuleTest(unittest.TestCase):
    """
    Verify Plesk detection covers favicon and header-value signals.
    """

    def test_plesklin_powered_by_header_is_detected(self):
        """Plesk rule must match PleskLin X-Powered-By values."""
        rule_path = REPO_DIR / "webapp" / "tags" / "favicon_plesk.yaml"
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

        self.assertIn("http_headval:x-powered-by.lk:plesklin", payload["query"])
        self.assertIn("http_favicon_mmhash:-134375033", payload["query"])
        self.assertIn("product:plesk", payload["tags"])
        self.assertIn("vendor:plesk", payload["tags"])


if __name__ == "__main__":
    unittest.main()
