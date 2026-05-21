#!/usr/bin/env python3
"""
Regression test for per-port parser result accumulation.
"""

import sys
from pathlib import Path
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
UTILS_DIR = ROOT_DIR / "webapp" / "app" / "utils"
sys.path.insert(0, str(UTILS_DIR))

from result_parser import parse_json  # pylint: disable=wrong-import-position


class ResultParserMultiPortTest(TestCase):
    """
    Verify repeated per-port scripts append values instead of overwriting them.
    """

    def test_banner_values_accumulate_across_ports(self):
        """
        Multiple banner scripts on different ports must all be indexed.
        """
        document = {
            "id": "multi-banner",
            "ip": "192.0.2.10",
            "body": {
                "endtime": "2026-05-20T00:00:00",
                "ports": [
                    {
                        "portid": "21",
                        "scripts": [
                            {
                                "id": "banner",
                                "output": "220---------- Welcome to Pure-FTPd [TLS] ----------",
                            }
                        ],
                    },
                    {
                        "portid": "143",
                        "scripts": [{"id": "banner", "output": "+OK Dovecot ready."}],
                    },
                ],
            },
        }

        result = parse_json(
            document,
            {
                "ONLINETLD": False,
                "TLDS": [],
                "TLDADD": [],
                "HTTP_HEADER_COLLECTION": {},
            },
            tag_rules=[],
        )

        self.assertEqual(
            result["banner"],
            [
                "220---------- Welcome to Pure-FTPd [TLS] ----------",
                "+OK Dovecot ready.",
            ],
        )


if __name__ == "__main__":
    main()
