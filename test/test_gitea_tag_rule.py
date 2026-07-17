#!/usr/bin/env python3
"""
Tests for Gitea tag-rule coverage.
"""

import unittest
from pathlib import Path

import yaml

REPO_DIR = Path(__file__).resolve().parent.parent


class GiteaTagRuleTest(unittest.TestCase):
    """
    Verify Gitea detection covers favicon and title signals.
    """

    def test_gitea_title_is_detected(self):
        """Gitea rule must match the default Gitea title."""
        rule_path = REPO_DIR / "webapp" / "tags" / "favicon_gitea.yaml"
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

        self.assertIn('http_title.lk:"Gitea: Git with a cup of tea"', payload["query"])
        self.assertIn("http_favicon_mmhash:1969970750", payload["query"])
        self.assertIn("product:gitea", payload["tags"])
        self.assertIn("vendor:gitea", payload["tags"])


if __name__ == "__main__":
    unittest.main()
