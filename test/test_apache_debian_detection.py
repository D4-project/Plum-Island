#!/usr/bin/env python3
"""Regression coverage for Apache on Debian detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


APACHE_GROUPS = [{"http_server.lk": ["Apache/"]}]
DEBIAN_GROUPS = [{"http_server.lk": ["(Debian)"]}]


class ApacheDebianDetectionTest(TestCase):
    """Verify independent Apache and Debian server banner detection."""

    def test_reported_server_banner_matches(self):
        self.assertTrue(
            document_matches_criteria_groups(
                {"http_server": ["Apache/2.4.25 (Debian)"]},
                APACHE_GROUPS,
            )
        )
        self.assertTrue(
            document_matches_criteria_groups(
                {"http_server": ["Apache/2.4.25 (Debian)"]}, DEBIAN_GROUPS
            )
        )

    def test_other_server_banners_do_not_match(self):
        for server in ("Apache/2.4.25 (Ubuntu)", "nginx/1.27.0", "lighttpd/1.4.82"):
            self.assertFalse(
                document_matches_criteria_groups(
                    {"http_server": [server]}, APACHE_GROUPS
                )
            )
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["Apache/2.4.25 (Ubuntu)"]}, DEBIAN_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        apache_rule = yaml.safe_load((ROOT_DIR / "webapp/tags/apache.yaml").read_text())
        debian_rule = yaml.safe_load((ROOT_DIR / "webapp/tags/debian.yaml").read_text())
        self.assertEqual(apache_rule["query"], 'http_server.lk:"Apache/"')
        self.assertIn('http_server.lk:"(Debian)"', debian_rule["query"])
        self.assertEqual(
            apache_rule["tags"], ["product:apache", "vendor:apache"]
        )
        self.assertEqual(debian_rule["tags"], ["vendor:debian", "product:debian"])


if __name__ == "__main__":
    main()
