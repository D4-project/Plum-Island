#!/usr/bin/env python3
"""
Regression tests for parser IP filtering.
"""

import sys
from pathlib import Path
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
UTILS_DIR = ROOT_DIR / "webapp" / "app" / "utils"
sys.path.insert(0, str(UTILS_DIR))

from result_parser import parse_json  # pylint: disable=wrong-import-position

PARSER_CONFIG = {
    "ONLINETLD": False,
    "TLDS": [],
    "TLDADD": [],
    "HTTP_HEADER_COLLECTION": {},
}


def build_document(ip_address):
    """
    Build a minimal Nmap-like document consumed by parse_json.
    """
    return {
        "id": f"doc-{ip_address}",
        "ip": ip_address,
        "body": {
            "endtime": "2026-07-09T00:00:00",
            "ports": [
                {
                    "portid": "22",
                    "scripts": [{"id": "banner", "output": "SSH-2.0-OpenSSH"}],
                }
            ],
        },
    }


class ResultParserExternalIpTest(TestCase):
    """
    Verify parser drops non-external scan results.
    """

    def test_non_external_ips_are_skipped(self):
        """
        Internal, loopback, multicast, and reserved IPs must not be indexed.
        """
        skipped_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ]

        for ip_address in skipped_ips:
            with self.subTest(ip_address=ip_address):
                result = parse_json(
                    build_document(ip_address),
                    PARSER_CONFIG,
                    tag_rules=[],
                )
                self.assertIsNone(result)

    def test_external_ips_are_parsed(self):
        """
        Public IPv4 and IPv6 scan results should still be indexed.
        """
        for ip_address in ["93.184.216.34", "2001:4860:4860::8888"]:
            with self.subTest(ip_address=ip_address):
                result = parse_json(
                    build_document(ip_address),
                    PARSER_CONFIG,
                    tag_rules=[],
                )
                self.assertIsNotNone(result)
                self.assertEqual(result["ip"], ip_address)
                self.assertEqual(result["port"], ["22"])


if __name__ == "__main__":
    main()
