#!/usr/bin/env python3
"""
Tests for Ivanti tag-rule coverage.
"""

import unittest
from pathlib import Path

import yaml

REPO_DIR = Path(__file__).resolve().parent.parent


class IvantiTagRuleTest(unittest.TestCase):
    """
    Verify Ivanti detection covers favicon hash values.
    """

    def test_ivanti_favicon_hashes_are_detected(self):
        """Ivanti rule must match known favicon hashes."""
        rule_path = REPO_DIR / "webapp" / "tags" / "favicon_ivanti.yaml"
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

        self.assertIn("http_favicon_mmhash:1983356674", payload["query"])
        self.assertIn(
            "http_favicon_md5:182336a576ac6ee5aca724e6c718b7d6",
            payload["query"],
        )
        self.assertIn(
            "http_favicon_sha256:968ba268be72e7ce0c2797110c346321c16b9862214b23b0e9af37adac8b005f",
            payload["query"],
        )
        self.assertIn("product:ivanti", payload["tags"])
        self.assertIn("vendor:ivanti", payload["tags"])


if __name__ == "__main__":
    unittest.main()
