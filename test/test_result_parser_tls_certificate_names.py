#!/usr/bin/env python3
"""
Regression tests for TLS certificate hostname/domain extraction.
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


def build_tls_document():
    """
    Build a minimal document with certificate-only Arcus hostnames.
    """
    san = "DNS:*.ad.arcus.lu, DNS:*.arcus.lu, DNS:*.ARCUS.lu."
    return {
        "id": "tls-cert-hostnames",
        "ip": "85.93.198.210",
        "body": {
            "endtime": "2026-07-16T00:00:00",
            "hostnames": [],
            "ports": [
                {
                    "portid": "443",
                    "scripts": [
                        {
                            "id": "ssl-cert",
                            "issuer": {
                                "commonName": "YR2",
                                "organizationName": "Let us Encrypt",
                                "countryName": "US",
                            },
                            "subject": {"commonName": "*.Arcus.LU."},
                            "extensions": {
                                "X509v3 Subject Alternative Name": san,
                            },
                            "md5": "md5-value",
                            "sha1": "sha1-value",
                            "sha256": "sha256-value",
                        }
                    ],
                }
            ],
        },
    }


class ResultParserTlsCertificateNamesTest(TestCase):
    """
    Verify TLS certificate names contribute normalized domain search fields.
    """

    def test_certificate_san_dns_names_feed_domain_search(self):
        """
        Wildcard DNS SAN entries must index registered domains without wildcards.
        """
        result = parse_json(build_tls_document(), PARSER_CONFIG, tag_rules=[])

        self.assertIn("arcus.lu", result["domain"])
        self.assertIn("ad.arcus.lu", result["fqdn"])
        self.assertIn("arcus.lu", result["fqdn"])
        self.assertNotIn("*.arcus.lu", result["domain"])
        self.assertNotIn("*.arcus.lu", result["fqdn"])
        self.assertEqual(result.get("fqdn_requested"), None)
        self.assertEqual(result.get("domain_requested"), None)

    def test_certificate_metadata_fields_stay_raw(self):
        """
        Existing x509 fields must remain available for direct certificate search.
        """
        result = parse_json(build_tls_document(), PARSER_CONFIG, tag_rules=[])

        self.assertEqual(result["x509_issuer"], ["YR2"])
        self.assertEqual(result["x509_subject"], ["*.Arcus.LU."])
        self.assertEqual(
            result["x509_san"],
            ["DNS:*.ad.arcus.lu, DNS:*.arcus.lu, DNS:*.ARCUS.lu."],
        )


if __name__ == "__main__":
    main()
