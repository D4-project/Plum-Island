#!/usr/bin/env python3
"""Generic header collection coverage, independent of YAML detection rules."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp"))

from app.utils.result_parser import parse_json  # pylint: disable=wrong-import-position
from app.utils.tagrules import (  # pylint: disable=wrong-import-position
    analyze_header_dependencies,
)
from app.models import (  # pylint: disable=wrong-import-position
    DEFAULT_COLLECTED_HEADERS,
    headers_required_by_tag_rules,
)


class HeaderCollectionTest(TestCase):
    """Verify parser normalization and dynamic header dependency handling."""

    def test_header_is_normalized_and_value_is_not_stored(self):
        """Presence-only collection must not retain the header value."""
        document = {
            "id": "header-collection",
            "ip": "93.184.216.34",
            "body": {
                "endtime": "2026-09-08T00:00:00",
                "hostnames": [],
                "ports": [
                    {
                        "portid": "80",
                        "scripts": [
                            {
                                "id": "http-headers",
                                "output": "HTTP/1.1 200 OK\r\nX-Example-Node: MAIN_SERVER\r\n",
                            }
                        ],
                    }
                ],
            },
        }
        result = parse_json(
            document,
            {
                "ONLINETLD": False,
                "TLDS": [],
                "TLDADD": [],
                "HTTP_HEADER_COLLECTION": {"x-example-node": False},
            },
            tag_rules=[],
        )
        self.assertEqual(result["http_header"], ["x-example-node"])
        self.assertNotIn("http_headval", result)

    def test_rule_headers_are_dynamic_not_global_defaults(self):
        """Rule-specific headers must not depend on the built-in collection."""
        self.assertNotIn("x-example-node", DEFAULT_COLLECTED_HEADERS)
        rule = SimpleNamespace(
            query="http_header:X-Example-Node OR http_headval:X-Custom-Trace"
        )
        self.assertEqual(
            headers_required_by_tag_rules([rule]),
            {"x-example-node": False, "x-custom-trace": True},
        )

    def test_compiled_dependencies_keep_shared_value_requirement(self):
        """A value predicate takes precedence over presence-only collection."""
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
        """Legacy value syntax must resolve to the header name only."""
        rule = SimpleNamespace(
            query=(
                "http_headval:www-authenticate.bg:realm OR "
                "http_headval:www-authenticate.lk:example"
            )
        )
        self.assertEqual(
            headers_required_by_tag_rules([rule]),
            {"www-authenticate": True},
        )


if __name__ == "__main__":
    main()
