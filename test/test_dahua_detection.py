#!/usr/bin/env python3
"""Regression coverage for Dahua camera detection signals."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


DAHUA_GROUPS = [
    {"http_favicon_mmhash": ["-1466785234"]},
    {"http_favicon_mmhash": ["1653394551"]},
    {"http_favicon_md5": ["a437e84d20c9cf7442fffab49e0f07e7"]},
    {
        "http_favicon_sha256": [
            "6fe49ae6a389a8cc3ef2866682443909dbb6987ca1918392b6e5d6473cbdd969"
        ]
    },
    {"x509_issuer.lk": ["dahua"]},
]


class DahuaDetectionTest(TestCase):
    """Verify Dahua favicon and certificate signals."""

    def test_each_signal_matches(self):
        documents = (
            {"http_favicon_mmhash": ["-1466785234"]},
            {"http_favicon_mmhash": ["1653394551"]},
            {"http_favicon_md5": ["a437e84d20c9cf7442fffab49e0f07e7"]},
            {
                "http_favicon_sha256": [
                    "6fe49ae6a389a8cc3ef2866682443909dbb6987ca1918392b6e5d6473cbdd969"
                ]
            },
            {"x509_issuer": ["CN: Dahua Device NVR CA"]},
        )
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, DAHUA_GROUPS))

    def test_unrelated_values_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"x509_issuer": ["CN: Axis Camera CA"]}, DAHUA_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_signals_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/favicon_dahua.yaml").read_text())
        self.assertIn("http_favicon_mmhash:1653394551", rule["query"])
        self.assertIn("http_favicon_md5:a437e84d20c9cf7442fffab49e0f07e7", rule["query"])
        self.assertIn("x509_issuer.lk:dahua", rule["query"])
        self.assertEqual(
            rule["tags"], ["product:dahua", "type:camera", "vendor:dahua"]
        )


if __name__ == "__main__":
    main()
