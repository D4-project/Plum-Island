#!/usr/bin/env python3
"""Regression coverage for OPNsense detection signals."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


OPNSENSE_GROUPS = [
    {"http_favicon_mmhash": ["-1148190371"]},
    {"http_server.lk": ["OPNsense"]},
    {"x509_issuer.lk": ["CN: OPNsense.internal"]},
    {"http_title": ["Error | OPNsense"]},
    {"http_favicon_mmhash": ["-1068289244"]},
    {"http_favicon_md5": ["18c7c53e5c7df0ea7a891bf9d99a610c"]},
    {
        "http_favicon_sha256": [
            "3cd53dc40912bb3b9c4f019f2090ae3a2f978dc509cdf916e6f8f41b7924b50e"
        ]
    },
]


class OpnsenseDetectionTest(TestCase):
    """Verify every OPNsense signal and an unrelated negative."""

    def test_each_signal_matches(self):
        documents = (
            {"http_favicon_mmhash": ["-1148190371"]},
            {"http_server": ["OPNsense"]},
            {"x509_issuer": ["CN: OPNsense.internal"]},
            {"http_title": ["Error | OPNsense"]},
            {"http_favicon_mmhash": ["-1068289244"]},
            {"http_favicon_md5": ["18c7c53e5c7df0ea7a891bf9d99a610c"]},
            {
                "http_favicon_sha256": [
                    "3cd53dc40912bb3b9c4f019f2090ae3a2f978dc509cdf916e6f8f41b7924b50e"
                ]
            },
        )
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, OPNSENSE_GROUPS))

    def test_unrelated_values_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_server": ["pfSense"]}, OPNSENSE_GROUPS
            )
        )

    def test_yaml_rule_preserves_existing_signal_and_tags(self):
        rule = yaml.safe_load(
            (ROOT_DIR / "webapp/tags/favicon_opnsense.yaml").read_text()
        )
        self.assertIn("http_favicon_mmhash:-1148190371", rule["query"])
        self.assertIn("http_server.lk:OPNsense", rule["query"])
        self.assertIn("http_favicon_md5:18c7c53e5c7df0ea7a891bf9d99a610c", rule["query"])
        self.assertEqual(rule["tags"], ["product:opnsense", "vendor:opnsense"])


if __name__ == "__main__":
    main()
