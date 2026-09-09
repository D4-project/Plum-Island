#!/usr/bin/env python3
"""Regression coverage for BVPN certificate detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


BVPN_GROUPS = [{"x509_subject.lk": ["bvpn.com"]}]


class BvpnDetectionTest(TestCase):
    """Verify BVPN certificate matching is case-insensitive and specific."""

    def test_bvpn_certificate_matches(self):
        for subject in ("CN=bvpn.com", "CN=Gateway.BVPN.COM, O=BVpn"):
            self.assertTrue(
                document_matches_criteria_groups(
                    {"x509_subject": [subject]}, BVPN_GROUPS
                )
            )

    def test_unrelated_certificate_does_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"x509_subject": ["CN=example.com"]}, BVPN_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/bvpn.yaml").read_text())
        self.assertEqual(rule["query"], "x509_subject.lk:bvpn.com")
        self.assertEqual(
            rule["tags"], ["product:bvpn", "vendor:bvpn", "type:vpn"]
        )


if __name__ == "__main__":
    main()
