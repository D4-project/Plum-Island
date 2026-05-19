#!/usr/bin/env python3
"""
Regression test for concurrent result_parser config isolation.
"""

from concurrent.futures import ThreadPoolExecutor
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
UTILS_DIR = ROOT_DIR / "webapp" / "app" / "utils"
sys.path.insert(0, str(UTILS_DIR))

from result_parser import parse_json  # pylint: disable=wrong-import-position


def build_document(hostname, headers):
    """
    Build a minimal Nmap-like document consumed by parse_json.
    """
    return {
        "id": hostname,
        "ip": "192.0.2.1",
        "body": {
            "endtime": "2026-05-19T00:00:00",
            "hostnames": [{"name": hostname, "type": "user"}],
            "ports": [
                {
                    "portid": "80",
                    "scripts": [
                        {
                            "id": "http-headers",
                            "output": headers,
                        }
                    ],
                }
            ],
        },
    }


def parse_with_config(hostname, tld, header_name, header_value):
    """
    Parse one document with a config unique to this call.
    """
    config = {
        "ONLINETLD": True,
        "TLDS": [tld],
        "TLDADD": [],
        "HTTP_HEADER_COLLECTION": {header_name: True},
    }
    document = build_document(
        hostname,
        f"{header_name}: {header_value}\nX-Other: ignored\n",
    )
    return parse_json(document, config, tag_rules=[])


class ResultParserConfigIsolationTest(TestCase):
    """
    Verify parser config stays isolated across concurrent calls.
    """

    def test_concurrent_parse_uses_call_local_config(self):
        """
        Concurrent parse_json calls must not share TLD/header config.
        """
        cases = [
            ("alpha.example.com", "example.com", "com", "X-Alpha", "A"),
            ("beta.example.net", "example.net", "net", "X-Beta", "B"),
        ]

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            for case in cases:
                hostname, _domain, tld, header, value = case
                for _ in range(50):
                    futures.append(
                        (
                            case,
                            executor.submit(
                                parse_with_config, hostname, tld, header, value
                            ),
                        )
                    )

        for case, future in futures:
            hostname, domain, _tld, header, value = case
            result = future.result()
            expected_header = header.lower()
            self.assertEqual(result["fqdn_requested"], [hostname])
            self.assertEqual(result["domain_requested"], [domain])
            self.assertEqual(result["http_header"], [expected_header])
            self.assertEqual(
                result["http_headval"], [f"{expected_header}:{value.lower()}"]
            )


if __name__ == "__main__":
    main()
