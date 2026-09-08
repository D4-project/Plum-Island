#!/usr/bin/env python3
"""Regression coverage for Cisco switch favicon detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from result_parser import parse_json  # pylint: disable=wrong-import-position
from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


SWITCH_GROUPS = [
    {"http_favicon_mmhash": ["-627596452"]},
    {"http_favicon_md5": ["c859808fad284ad07d0c7c6836d18b8e"]},
]


def build_document(favicon):
    """Build a minimal scan document containing one favicon result."""
    return {
        "id": "cisco-switch-detection",
        "ip": "93.184.216.34",
        "body": {
            "endtime": "2026-09-08T00:00:00",
            "hostnames": [],
            "ports": [
                {
                    "portid": "443",
                    "scripts": [
                        {"id": "http-mm-sha-favicon", **favicon},
                    ],
                }
            ],
        },
    }


class CiscoSwitchDetectionTest(TestCase):
    """Verify both supplied Cisco switch favicon fingerprints."""

    @staticmethod
    def parse(document):
        return parse_json(
            document,
            {
                "ONLINETLD": False,
                "TLDS": [],
                "TLDADD": [],
                "HTTP_HEADER_COLLECTION": {},
            },
            tag_rules=[],
        )

    def test_mmhash_and_md5_each_match(self):
        for favicon in (
            {"favicon_mmhash": "-627596452"},
            {"favicon_md5": "c859808fad284ad07d0c7c6836d18b8e"},
        ):
            result = self.parse(build_document(favicon))
            self.assertTrue(document_matches_criteria_groups(result, SWITCH_GROUPS))

    def test_unrelated_fingerprint_does_not_match(self):
        result = self.parse(
            build_document(
                {
                    "favicon_mmhash": "1234",
                    "favicon_md5": "deadbeef",
                }
            )
        )
        self.assertFalse(document_matches_criteria_groups(result, SWITCH_GROUPS))

    def test_yaml_rule_contains_supplied_signals(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/cisco_switch.yaml").read_text())
        self.assertIn("http_favicon_mmhash:-627596452", rule["query"])
        self.assertIn(
            "http_favicon_md5:c859808fad284ad07d0c7c6836d18b8e",
            rule["query"],
        )


if __name__ == "__main__":
    main()
