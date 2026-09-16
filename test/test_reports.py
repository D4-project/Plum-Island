#!/usr/bin/env python3
"""Regression coverage for protocol-grouped Markdown reports."""

from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp"))

from app.utils.reports import (  # pylint: disable=wrong-import-position
    build_report_markdown,
    collect_report_passive_dns_fqdns,
)

REPORT = SimpleNamespace(
    name="Protocol report",
    description="",
    query="port:443",
    schedule_type="monthly",
)


class ReportProtocolViewsTest(TestCase):
    """Verify report protocol sections and Passive DNS metadata rendering."""

    def test_protocol_views_include_overlaps_and_skip_empty_sections(self):
        """Web and mail overlap while Other retains only unclassified hosts."""
        markdown = build_report_markdown(
            REPORT,
            {
                "results": {
                    "192.0.2.1": {"web"},
                    "192.0.2.2": {"mail"},
                    "192.0.2.3": {"both"},
                    "192.0.2.4": {"other"},
                }
            },
            {"192.0.2.1": ["443"]},
            {},
            None,
            None,
            per_ip_tags={
                "192.0.2.1": ["proto:http"],
                "192.0.2.2": ["proto:imap"],
                "192.0.2.3": ["proto:https", "proto:smtp"],
                "192.0.2.4": ["vendor:example"],
            },
        )

        web_section = markdown.split("## Web hosts", 1)[1].split("## Mail related", 1)[
            0
        ]
        mail_section = markdown.split("## Mail related", 1)[1].split("## Other", 1)[0]
        other_section = markdown.split("## Other", 1)[1].split("## Hosts", 1)[0]
        self.assertIn("- 192.0.2.1", web_section)
        self.assertIn("- 192.0.2.3", web_section)
        self.assertIn("- 192.0.2.2", mail_section)
        self.assertIn("- 192.0.2.3", mail_section)
        self.assertIn("- 192.0.2.4", other_section)
        self.assertNotIn("- 192.0.2.1", other_section)
        self.assertLess(markdown.index("## Other"), markdown.index("## Hosts"))
        self.assertLess(markdown.index("## Hosts"), markdown.index("## Disclaimer"))

        web_only = build_report_markdown(
            REPORT,
            {"results": {"192.0.2.1": {"web"}}},
            {},
            {},
            None,
            None,
            per_ip_tags={"192.0.2.1": ["proto:http"]},
        )
        self.assertIn("## Web hosts", web_only)
        self.assertNotIn("## Mail related", web_only)
        self.assertNotIn("## Other", web_only)

    def test_fqdn_sources_and_pdns_timestamps_are_rendered(self):
        """PTR, requested, and PDNS names retain precedence and timestamps."""
        markdown = build_report_markdown(
            REPORT,
            {"results": {"192.0.2.1": {"web"}}},
            {},
            {},
            None,
            None,
            per_ip_tags={"192.0.2.1": ["proto:https"]},
            per_ip_requested_fqdns={"192.0.2.1": ["requested.example"]},
            per_ip_ptr_fqdns={"192.0.2.1": ["ptr.example"]},
            per_ip_pdns_fqdns={
                "192.0.2.1": [
                    {"fqdn": "pdns.example", "last_seen": 1700000000},
                    {"fqdn": "unknown.example", "last_seen": None},
                ]
            },
        )

        hosts = markdown.split("## Hosts", 1)[1]
        self.assertLess(
            hosts.index("ptr.example (ptr)"), hosts.index("requested.example")
        )
        self.assertLess(
            hosts.index("requested.example"), hosts.index("pdns.example (pdns)")
        )
        self.assertIn("last seen: 2023-11-14 22:13:20 UTC", hosts)
        self.assertIn("unknown.example (pdns) — last seen: N/A", hosts)

    def test_global_fqdn_sections_are_domain_sorted_and_separate_pdns(self):
        """Detected and Passive DNS FQDNs remain separate sorted sections."""
        markdown = build_report_markdown(
            REPORT,
            {"results": {"192.0.2.1": {"web"}}},
            {},
            {},
            None,
            None,
            per_ip_requested_fqdns={"192.0.2.1": ["www.example.com", "mail.alpha.net"]},
            per_ip_ptr_fqdns={"192.0.2.1": ["api.example.com"]},
            per_ip_pdns_fqdns={
                "192.0.2.1": [
                    {"fqdn": "legacy.example.com", "last_seen": 1700000000},
                    {"fqdn": "old.alpha.net", "last_seen": None},
                ]
            },
        )

        detected = markdown.split("## FQDN detected", 1)[1].split(
            "## Passive DNS FQDN detected", 1
        )[0]
        passive_dns = markdown.split("## Passive DNS FQDN detected", 1)[1].split(
            "## Hosts", 1
        )[0]
        self.assertLess(
            detected.index("api.example.com"), detected.index("www.example.com")
        )
        self.assertLess(
            detected.index("www.example.com"), detected.index("mail.alpha.net")
        )
        self.assertNotIn("legacy.example.com", detected)
        self.assertIn(
            "legacy.example.com — last seen: 2023-11-14 22:13:20 UTC", passive_dns
        )
        self.assertIn("old.alpha.net — last seen: N/A", passive_dns)
        self.assertLess(
            markdown.index("## New opened port"), markdown.index("## FQDN detected")
        )
        self.assertLess(markdown.index("## FQDN detected"), markdown.index("## Hosts"))

    @patch("app.utils.reports.requests.get")
    def test_passive_dns_retains_time_last_and_tolerates_failures(self, request_get):
        """CIRCL time_last is retained while request failures keep reports usable."""
        response = Mock()
        response.text = (
            '{"rrtype":"A","rdata":"pdns.example","time_last":"1700000000"}\n'
            '{"rrtype":"A","rdata":"unknown.example","time_last":"invalid"}\n'
        )
        request_get.return_value = response

        records = collect_report_passive_dns_fqdns(
            {"PASSIVE_USER": "user", "PASSIVE_PWD": "password"},
            ["192.0.2.1"],
            {},
        )
        self.assertEqual(
            records,
            {
                "192.0.2.1": [
                    {"fqdn": "pdns.example", "last_seen": 1700000000},
                    {"fqdn": "unknown.example", "last_seen": None},
                ]
            },
        )

        request_get.side_effect = requests.RequestException("offline")
        self.assertEqual(
            collect_report_passive_dns_fqdns(
                {"PASSIVE_USER": "user", "PASSIVE_PWD": "password"},
                ["192.0.2.1"],
                {},
            ),
            {},
        )


if __name__ == "__main__":
    main()
