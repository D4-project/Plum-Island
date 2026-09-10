#!/usr/bin/env python3
"""Regression coverage for Apache JMeter Dashboard detection."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


JMETER_GROUPS = [
    {"http_favicon_mmhash": ["-68185513"]},
    {"http_favicon_md5": ["a56d2f3884131eaf85b94c9b73fbfa21"]},
    {
        "http_favicon_sha256": [
            "d29a6a3499632cb6cf7caeeb30746194bd8fd68ba462d0061b384d1583dfd7c0"
        ]
    },
    {"http_title": ["Apache JMeter Dashboard"]},
]


class JmeterDetectionTest(TestCase):
    """Verify each JMeter signal and an unrelated negative."""

    def test_each_signal_matches(self):
        documents = (
            {"http_favicon_mmhash": ["-68185513"]},
            {"http_favicon_md5": ["a56d2f3884131eaf85b94c9b73fbfa21"]},
            {
                "http_favicon_sha256": [
                    "d29a6a3499632cb6cf7caeeb30746194bd8fd68ba462d0061b384d1583dfd7c0"
                ]
            },
            {"http_title": ["Apache JMeter Dashboard"]},
        )
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, JMETER_GROUPS))

    def test_unrelated_values_do_not_match(self):
        self.assertFalse(
            document_matches_criteria_groups(
                {"http_title": ["Apache Tomcat"]}, JMETER_GROUPS
            )
        )

    def test_yaml_rule_contains_expected_signals_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/jmeter.yaml").read_text())
        self.assertIn("http_favicon_mmhash:-68185513", rule["query"])
        self.assertIn('http_title.bg:"Apache JMeter Dashboard"', rule["query"])
        self.assertEqual(
            rule["tags"], ["product:jmeter", "type:dashboard", "vendor:apache"]
        )


if __name__ == "__main__":
    main()
