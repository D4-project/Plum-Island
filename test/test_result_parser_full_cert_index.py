#!/usr/bin/env python3
"""Tests for certificate enrichment at the Kvrocks boundary."""

import sys
from pathlib import Path
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp" / "app" / "utils"))

from result_parser import (  # pylint: disable=wrong-import-position
    parse_json,
    prepare_kvrocks_document,
)


PARSER_CONFIG = {
    "ONLINETLD": False,
    "TLDS": [],
    "TLDADD": [],
    "HTTP_HEADER_COLLECTION": {},
}


def build_document():
    """Build one raw scan result with a structured TLS certificate."""
    return {
        "id": "full-cert-index",
        "ip": "93.184.216.34",
        "body": {
            "endtime": "2026-09-10T00:00:00",
            "hostnames": [],
            "ports": [
                {
                    "portid": "443",
                    "scripts": [
                        {
                            "id": "ssl-cert",
                            "issuer": {
                                "commonName": "Dahua Device NVR CA",
                                "organizationName": "Zhejiang Dahua Technology Co.,Ltd.",
                                "countryName": "CN",
                            },
                            "subject": {
                                "commonName": "camera.example.org",
                                "organizationalUnitName": "Security",
                                "countryName": "CN",
                            },
                        }
                    ],
                }
            ],
        },
    }


class FullCertificateIndexTest(TestCase):
    """Verify enrichment is isolated from the public parser result."""

    def test_parse_json_output_is_unchanged_and_kvrocks_copy_is_enriched(self):
        raw_document = build_document()
        parsed = parse_json(raw_document, PARSER_CONFIG, tag_rules=[])
        parsed_snapshot = dict(parsed)

        indexed = prepare_kvrocks_document(raw_document, parsed, tag_rules=[])

        self.assertEqual(parsed, parsed_snapshot)
        self.assertEqual(parsed["x509_issuer"], ["Dahua Device NVR CA"])
        self.assertEqual(parsed["x509_subject"], ["camera.example.org"])
        self.assertEqual(
            indexed["x509_issuer_cn"], ["Dahua Device NVR CA"]
        )
        self.assertEqual(
            indexed["x509_issuer"],
            ["CN=Dahua Device NVR CA, O=Zhejiang Dahua Technology Co.\\,Ltd., C=CN"],
        )
        self.assertEqual(indexed["x509_subject_cn"], ["camera.example.org"])
        self.assertEqual(
            indexed["x509_subject"],
            ["CN=camera.example.org, OU=Security, C=CN"],
        )

    def test_certificate_values_are_escaped_and_raw_input_is_not_mutated(self):
        raw_document = build_document()
        raw_document["body"]["ports"][0]["scripts"][0]["issuer"][
            "organizationName"
        ] = "A\\B, C"
        parsed = parse_json(raw_document, PARSER_CONFIG, tag_rules=[])

        indexed = prepare_kvrocks_document(raw_document, parsed, tag_rules=[])

        self.assertEqual(
            indexed["x509_issuer"],
            ["CN=Dahua Device NVR CA, O=A\\\\B\\, C, C=CN"],
        )
        self.assertEqual(
            raw_document["body"]["ports"][0]["scripts"][0]["issuer"][
                "organizationName"
            ],
            "A\\B, C",
        )


if __name__ == "__main__":
    main()
