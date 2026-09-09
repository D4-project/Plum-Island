#!/usr/bin/env python3
"""Regression coverage for TeamCity header and favicon detections."""

import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))
sys.path.insert(0, str(ROOT_DIR / "webapp"))

from result_parser import parse_json  # pylint: disable=wrong-import-position
from tagrules import (  # pylint: disable=wrong-import-position
    analyze_header_dependencies,
    document_matches_criteria_groups,
)
from app.models import (  # pylint: disable=wrong-import-position
    DEFAULT_COLLECTED_HEADERS,
    headers_required_by_tag_rules,
)


TEAMCITY_GROUPS = [
    {"http_favicon_mmhash": ["-1944119648"]},
    {"http_header": ["teamcity-node-id"]},
    {"http_favicon_md5": ["cee18e28257988b40028043e65a6c2a3"]},
]


def build_document(header_output=None, favicon=None):
    """Build a minimal parsed scan document with optional TeamCity signals."""
    scripts = []
    if header_output is not None:
        scripts.append({"id": "http-headers", "output": header_output})
    if favicon is not None:
        scripts.append({"id": "http-mm-sha-favicon", **favicon})
    return {
        "id": "teamcity-detection",
        "ip": "93.184.216.34",
        "body": {
            "endtime": "2026-09-08T00:00:00",
            "hostnames": [],
            "ports": [{"portid": "8111", "scripts": scripts}],
        },
    }


class TeamCityDetectionTest(TestCase):
    """Verify each TeamCity signal and the default header collection behavior."""

    def parse(self, document):
        return parse_json(
            document,
            {
                "ONLINETLD": False,
                "TLDS": [],
                "TLDADD": [],
                "HTTP_HEADER_COLLECTION": {"teamcity-node-id": False},
            },
            tag_rules=[],
        )

    def test_node_header_is_normalized_and_value_is_not_stored(self):
        result = self.parse(
            build_document("HTTP/1.1 200 OK\r\nTeamCity-Node-Id: MAIN_SERVER\r\n")
        )
        self.assertEqual(result["http_header"], ["teamcity-node-id"])
        self.assertNotIn("http_headval", result)

    def test_each_teamcity_signal_matches(self):
        documents = [
            self.parse(build_document(favicon={"favicon_mmhash": "-1944119648"})),
            self.parse(build_document("TeamCity-Node-Id: MAIN_SERVER")),
            self.parse(build_document(favicon={"favicon_md5": "cee18e28257988b40028043e65a6c2a3"})),
        ]
        for document in documents:
            self.assertTrue(document_matches_criteria_groups(document, TEAMCITY_GROUPS))

    def test_unrelated_signals_do_not_match(self):
        document = self.parse(
            build_document(
                "Server: nginx\r\nX-Other-Header: value",
                {"favicon_mmhash": "1234", "favicon_md5": "deadbeef"},
            )
        )
        self.assertFalse(document_matches_criteria_groups(document, TEAMCITY_GROUPS))

    def test_yaml_rule_contains_all_signals(self):
        rule = yaml.safe_load((ROOT_DIR / "webapp/tags/favicon_teamcity.yaml").read_text())
        self.assertIn("http_favicon_mmhash:-1944119648", rule["query"])
        self.assertIn("http_header:teamcity-node-id", rule["query"])
        self.assertIn("http_favicon_md5:cee18e28257988b40028043e65a6c2a3", rule["query"])

    def test_rule_headers_are_dynamic_not_global_defaults(self):
        self.assertNotIn("teamcity-node-id", DEFAULT_COLLECTED_HEADERS)

        class Rule:
            query = "http_header:TeamCity-Node-Id OR http_headval:X-Custom-Trace"

        self.assertEqual(
            headers_required_by_tag_rules([Rule()]),
            {"teamcity-node-id": False, "x-custom-trace": True},
        )

    def test_compiled_dependencies_keep_shared_value_requirement(self):
        result = analyze_header_dependencies(
            [
                {"http_header": ["x-shared"]},
                {"http_headval.lk": ["x-shared:proxy"]},
                {"http_header.bg": ["x-"]},
            ]
        )
        self.assertEqual(result["exact"], {"x-shared": True})
        self.assertEqual(result["ambiguous"], ["x-"])

    def test_legacy_header_fallback_strips_value_predicate(self):
        class Rule:
            query = (
                "http_headval:www-authenticate.bg:realm OR "
                "http_headval:www-authenticate.lk:rocketmq"
            )

        self.assertEqual(
            headers_required_by_tag_rules([Rule()]),
            {"www-authenticate": True},
        )


if __name__ == "__main__":
    main()
