"""Regression tests for centralized pyfaup domain handling."""

import sys
import unittest
from pathlib import Path
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp"))

from app.utils.domains import (  # pylint: disable=wrong-import-position
    is_hostname_syntax,
    parse_hostname,
)
from app.utils.ip_whois import (  # pylint: disable=wrong-import-position
    WhoisLookupError,
    _query_public_registry,
    lookup_domain_whois,
    lookup_network_whois,
)


class DomainParsingTest(unittest.TestCase):
    @patch("app.utils.ip_whois._query_server")
    def test_nontransferred_network_retains_cidr(self, query):
        for cidr, address in (
            ("192.0.2.0/24", "192.0.2.0"),
            ("2001:db8::/48", "2001:db8::"),
        ):
            with self.subTest(cidr=cidr):
                query.reset_mock(side_effect=True)
                query.side_effect = [
                    "refer: whois.ripe.net",
                    "IP record",
                    "CIDR record",
                ]
                self.assertEqual(lookup_network_whois(cidr), "CIDR record")
                self.assertEqual(
                    query.call_args_list,
                    [
                        call("whois.iana.org", cidr),
                        call("whois.ripe.net", address),
                        call("whois.ripe.net", cidr),
                    ],
                )

    @patch("app.utils.ip_whois._query_server")
    def test_transferred_cidr_preserves_original_network(self, query):
        query.side_effect = [
            "refer: whois.apnic.net",
            "descr: Transferred to the RIPE region on 2021-12-02T13:43:36Z.",
            "inetnum: 180.149.36.0 - 180.149.36.255",
            "inetnum: 180.149.36.0 - 180.149.39.255\nnetname: LU-GCORELABS",
        ]
        self.assertIn("LU-GCORELABS", lookup_network_whois("180.149.36.0/22"))
        self.assertEqual(
            query.call_args_list,
            [
                call("whois.iana.org", "180.149.36.0/22"),
                call("whois.apnic.net", "180.149.36.0"),
                call("whois.ripe.net", "180.149.36.0"),
                call("whois.ripe.net", "180.149.36.0/22"),
            ],
        )

    @patch("app.utils.ip_whois._query_server")
    def test_ipv6_transfer_and_single_host(self, query):
        query.side_effect = [
            "refer: whois.arin.net",
            "ReferralServer: whois://whois.ripe.net:43",
            "IPv6 record",
        ]
        self.assertEqual(lookup_network_whois("2001:db8::1"), "IPv6 record")
        self.assertEqual(
            query.call_args_list[-1], call("whois.ripe.net", "2001:db8::1")
        )
        self.assertEqual(query.call_count, 3)

    @patch("app.utils.ip_whois._query_server")
    def test_network_referrals_are_bounded_and_allowlisted(self, query):
        for referral in (
            "refer: whois.apnic.net",
            "ReferralServer: whois://127.0.0.1",
            "whois: whois.ripe.net.attacker.example",
        ):
            with self.subTest(referral=referral):
                query.reset_mock(side_effect=True)
                query.side_effect = ["refer: whois.apnic.net", referral]
                with self.assertRaises(WhoisLookupError):
                    lookup_network_whois("180.149.36.0/22")
                self.assertEqual(query.call_count, 2)

    @patch("app.utils.ip_whois._query_server")
    def test_empty_destination_is_not_replaced_with_parent_record(self, query):
        query.side_effect = [
            "refer: whois.apnic.net",
            "descr: Transferred to the RIPE region on 2021-12-02.",
            "",
        ]
        with self.assertRaises(WhoisLookupError):
            lookup_network_whois("180.149.36.0/22")

    def test_multilabel_public_suffix(self):
        self.assertEqual(
            parse_hostname("Api.Mail.Example.CO.UK.")["domain"], "example.co.uk"
        )
        self.assertEqual(parse_hostname("api.mail.example.co.uk")["host"], "api.mail")

    def test_private_suffix_requires_explicit_allowance(self):
        self.assertIsNone(parse_hostname("api.example.local"))
        self.assertEqual(
            parse_hostname("api.example.local", ["local"])["domain"], "example.local"
        )

    def test_hostname_syntax_is_independent_of_suffix_list(self):
        self.assertTrue(is_hostname_syntax("com.unrwa.encd"))
        self.assertIsNone(parse_hostname("com.unrwa.encd"))
        for value in ("-sV", "foo/bar.com", "a..example.com", "8.8.8.999"):
            with self.subTest(value=value):
                self.assertFalse(is_hostname_syntax(value))

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
