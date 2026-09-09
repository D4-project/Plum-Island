#!/usr/bin/env python3
"""Regression coverage for NordVPN domain and port detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


NORDVPN_GROUPS = [{"domain": ["nordvpn.com"], "port": ["8443"]}]


class NordVpnDetectionTest(TestCase):
    """Verify the NordVPN rule requires both identifying fields."""

    def test_domain_and_port_match(self):
        document = {"domain": ["nordvpn.com"], "port": ["8443"]}
        self.assertTrue(document_matches_criteria_groups(document, NORDVPN_GROUPS))

    def test_other_domain_or_port_does_not_match(self):
        for document in (
            {"domain": ["nordvpn.com"], "port": ["443"]},
            {"domain": ["example.com"], "port": ["8443"]},
        ):
            self.assertFalse(
                document_matches_criteria_groups(document, NORDVPN_GROUPS)
            )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/nordvpn.yaml").read_text())
        self.assertEqual(rule["query"], "domain:nordvpn.com AND port:8443")
        self.assertEqual(
            rule["tags"], ["product:nordvpn", "vendor:nordvpn", "type:vpn"]
        )


if __name__ == "__main__":
    main()
