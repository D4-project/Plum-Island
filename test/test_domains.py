"""Regression tests for centralized pyfaup domain handling."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp"))

from app.utils.domains import parse_hostname  # pylint: disable=wrong-import-position
from app.utils.ip_whois import (  # pylint: disable=wrong-import-position
    WhoisLookupError,
    _query_public_registry,
    lookup_domain_whois,
    lookup_network_whois,
)


class DomainParsingTest(unittest.TestCase):
    def test_multilabel_public_suffix(self):
        self.assertEqual(parse_hostname("Api.Mail.Example.CO.UK.")["domain"], "example.co.uk")
        self.assertEqual(parse_hostname("api.mail.example.co.uk")["host"], "api.mail")

    def test_private_suffix_requires_explicit_allowance(self):
        self.assertIsNone(parse_hostname("api.example.local"))
        self.assertEqual(
            parse_hostname("api.example.local", ["local"])["domain"], "example.local"
        )

    def test_invalid_hostnames_rejected(self):
        for value in ("foo/bar.com", "example.com:43", "-bad.com", "a..example.com"):
            with self.subTest(value=value):
                self.assertIsNone(parse_hostname(value))

    @patch("app.utils.ip_whois._query_public_registry", return_value="domain record")
    @patch("app.utils.ip_whois._query_server", return_value="whois: whois.nic.uk")
    def test_domain_whois_uses_registered_domain(self, query_iana, query_registry):
        self.assertEqual(
            lookup_domain_whois("api.mail.example.co.uk"),
            ("example.co.uk", "domain record"),
        )
        query_iana.assert_called_once_with("whois.iana.org", "uk")
        query_registry.assert_called_once_with("whois.nic.uk", "example.co.uk")

    def test_unknown_suffix_cannot_trigger_whois(self):
        with self.assertRaises(WhoisLookupError):
            lookup_domain_whois("api.example.local")

    @patch("app.utils.ip_whois.socket.socket")
    @patch("app.utils.ip_whois.socket.getaddrinfo")
    def test_registry_referral_cannot_connect_to_private_ip(self, resolve, connect):
        resolve.return_value = [(2, 1, 6, "", ("127.0.0.1", 43))]
        with self.assertRaises(WhoisLookupError):
            _query_public_registry("whois.example.com", "example.com")
        connect.assert_not_called()

    @patch("app.utils.ip_whois._query_server")
    def test_arin_duplicate_notice_is_removed(self, query_server):
        """Keep one ARIN notice when the registry repeats it at the end."""
        notice = (
            "\n#\n"
            "# ARIN WHOIS data and services are subject to the Terms of Use\n"
            "# available at: https://www.arin.net/resources/registry/whois/tou/\n"
            "#\n"
            "# If you see inaccuracies in the results, please report at\n"
            "# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/\n"
            "#\n"
            "# Copyright 1997-2026, American Registry for Internet Numbers, Ltd.\n"
            "#\n\n"
        )
        query_server.side_effect = [
            "refer: whois.arin.net",
            notice + "NetName: GOOGLE-CLOUD\n" + notice,
        ]
        result = lookup_network_whois("35.246.198.116")
        query_server.assert_any_call("whois.arin.net", "n 35.246.198.116")
        self.assertEqual(result.count("# ARIN WHOIS data"), 1)
        self.assertIn("NetName: GOOGLE-CLOUD", result)


if __name__ == "__main__":
    unittest.main()
