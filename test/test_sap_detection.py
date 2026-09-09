#!/usr/bin/env python3
"""Regression coverage for generic SAP detection signals."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from tagrules import document_matches_criteria_groups  # pylint: disable=wrong-import-position


SAP_GROUPS = [
    {"http_title.bg": ["SAP Commerce Cloud"]},
    {"x509_subject.lk": ["SAP Trust Community"]},
    {"x509_subject.lk": ["SAP Commerce"]},
    {"http_title.lk": ["SAP PPM"]},
]


class SapDetectionTest(TestCase):
    """Verify every reported SAP signal and unrelated negatives."""

    def test_each_sap_signal_matches(self):
        documents = (
            {"http_title": ["SAP Commerce Cloud"]},
            {"x509_subject": ["CN=SAP Trust Community Root"]},
            {"x509_subject": ["CN=SAP Commerce Certificate"]},
            {"http_title": ["SAP PPM login"]},
        )
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, SAP_GROUPS))

    def test_unrelated_values_do_not_match(self):
        documents = (
            {"http_title": ["Commerce Cloud"]},
            {"x509_subject": ["CN=Trust Community"]},
            {"http_title": ["SAP ERP"]},
        )
        for document in documents:
            self.assertFalse(document_matches_criteria_groups(document, SAP_GROUPS))

    def test_yaml_rule_contains_expected_query_and_tags(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/sap.yaml").read_text())
        self.assertEqual(
            rule["query"],
            'http_title.bg:"SAP Commerce Cloud" OR '
            'x509_subject.lk:"SAP Trust Community" OR '
            'x509_subject.lk:"SAP Commerce" OR http_title.lk:"SAP PPM"',
        )
        self.assertEqual(rule["tags"], ["product:sap", "vendor:sap"])


if __name__ == "__main__":
    main()
