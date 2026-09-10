#!/usr/bin/env python3
"""Regression coverage for Pterodactyl detection signals."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


PTERODACTYL_GROUPS = [
    {"http_favicon_mmhash": ["846001371"]},
    {"http_favicon_md5": ["17ce6e2889f7a873a72564283f47cab4"]},
    {
        "http_favicon_sha256": [
            "eeb77a3447905ef66a0e44be6f28c29ed8e6aaf59214fd0bfb54df1dbdabd931"
        ]
    },
    {"http_title": ["Pterodactyl"]},
]


class PterodactylDetectionTest(TestCase):
    """Verify each Pterodactyl signal and an unrelated negative."""

    def test_each_signal_matches(self):
        documents = (
            {"http_favicon_mmhash": ["846001371"]},
            {"http_favicon_md5": ["17ce6e2889f7a873a72564283f47cab4"]},
            {
                "http_favicon_sha256": [
                    "eeb77a3447905ef66a0e44be6f28c29ed8e6aaf59214fd0bfb54df1dbdabd931"
                ]
            },
            {"http_title": ["Pterodactyl"]},
        )
        for document in documents:
            self.assertTrue(
                document_matches_criteria_groups(document, PTERODACTYL_GROUPS)
            )

    def test_unrelated_values_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_title": ["Plesk"]}, PTERODACTYL_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/pterodactyl.yaml").read_text())
        self.assertIn("http_favicon_mmhash:846001371", rule["query"])
        self.assertIn('http_title:"Pterodactyl"', rule["query"])
        self.assertEqual(
            rule["tags"], ["product:pterodactyl", "vendor:pterodactyl"]
        )


if __name__ == "__main__":
    main()
