#!/usr/bin/env python3
"""Regression coverage for protocol-grouped Markdown reports."""

from pathlib import Path
import sys
from datetime import datetime
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp"))

from app.utils.reports import (  # pylint: disable=wrong-import-position
    build_report_markdown,
    collect_report_passive_dns_fqdns,
    render_report_markdown_html,
    send_report_markdown,
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
                    "192.0.2.5": {"remote"},
                }
            },
            {"192.0.2.1": ["443"]},
            {},
            None,
            None,
            per_ip_tags={
                "192.0.2.1": [
                    "product:apache",
                    "vendor:apache",
                    "vendor:ubuntu",
                    "domain:circl.lu",
                    "proto:http",
                ],
                "192.0.2.2": ["proto:imap"],
                "192.0.2.3": ["proto:https", "proto:smtp"],
                "192.0.2.4": ["vendor:example"],
                "192.0.2.5": ["type:vpn"],
            },
        )

        web_section = markdown.split("## Webservices related host", 1)[1].split(
            "## Mail related", 1
        )[0]
        mail_section = markdown.split("## Mail related", 1)[1].split(
            "## Remote access", 1
        )[0]
        remote_section = markdown.split("## Remote access", 1)[1].split("## Other", 1)[
            0
        ]
        other_section = markdown.split("## Other", 1)[1].split(
            "## Full report dump", 1
        )[0]
        self.assertIn("- 192.0.2.1", web_section)
        self.assertIn("Hosts with at least one exposed web service.", web_section)
        self.assertIn("product:apache, vendor:ubuntu, proto:http", web_section)
        self.assertNotIn("vendor:apache", web_section)
        self.assertNotIn("domain:circl.lu", web_section)
        self.assertIn("- 192.0.2.3", web_section)
        self.assertIn("- 192.0.2.2", mail_section)
        self.assertIn("Hosts with at least one exposed mail service.", mail_section)
        self.assertIn("- 192.0.2.3", mail_section)
        self.assertIn("- 192.0.2.5", remote_section)
        self.assertIn(
            "Hosts with at least one exposed VPN, SSH, Telnet, or RDP service.",
            remote_section,
        )
        self.assertIn("- 192.0.2.4", other_section)
        self.assertNotIn("- 192.0.2.1", other_section)
        self.assertLess(
            markdown.index("## Other"), markdown.index("## Full report dump")
        )
        self.assertLess(
            markdown.index("## Full report dump"), markdown.index("## Disclaimer")
        )

        web_only = build_report_markdown(
            REPORT,
            {"results": {"192.0.2.1": {"web"}}},
            {},
            {},
            None,
            None,
            per_ip_tags={"192.0.2.1": ["proto:http"]},
        )
        self.assertIn("## Webservices related host", web_only)
        self.assertNotIn("## Mail related", web_only)
        self.assertNotIn("## Remote access", web_only)
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

        hosts = markdown.split("## Full report dump", 1)[1]
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
            datetime(2023, 11, 15),
            per_ip_requested_fqdns={
                "192.0.2.1": ["www.example.com", "mail.alpha.net"],
                "192.0.2.2": ["www.example.com"],
            },
            per_ip_ptr_fqdns={"192.0.2.1": ["api.example.com"]},
            per_ip_pdns_fqdns={
                "192.0.2.1": [
                    {"fqdn": "legacy.example.com", "last_seen": 1700000000},
                    {"fqdn": "old.alpha.net", "last_seen": None},
                ],
                "192.0.2.2": [
                    {"fqdn": "legacy.example.com", "last_seen": 1699999999},
                ],
            },
        )

        detected = markdown.split("## FQDN detected", 1)[1].split(
            "## FQDN discovered in Passive DNS", 1
        )[0]
        passive_dns = markdown.split("## FQDN discovered in Passive DNS", 1)[1].split(
            "## Other", 1
        )[0]
        self.assertLess(
            detected.index("api.example.com"), detected.index("www.example.com")
        )
        self.assertLess(
            detected.index("www.example.com"), detected.index("mail.alpha.net")
        )
        self.assertNotIn("legacy.example.com", detected)
        self.assertIn(
            "FQDNs (Fully Qualified domain names) detected from scanned hosts. "
            "These hostnames can be collected from any scan result fields, "
            "including records within certificates.",
            detected,
        )
        self.assertIn("www.example.com (192.0.2.1, 192.0.2.2)", detected)
        self.assertIn(
            "legacy.example.com (192.0.2.1, 192.0.2.2) — last seen: "
            "2023-11-14 22:13:20 UTC",
            passive_dns,
        )
        self.assertNotIn("old.alpha.net", passive_dns)
        self.assertIn(
            "Additional Passive DNS records not detected, observed within the last "
            "90 days.",
            passive_dns,
        )
        self.assertLess(
            markdown.index("## New opened port"), markdown.index("## FQDN detected")
        )
        self.assertLess(
            markdown.index("## FQDN detected"), markdown.index("## Full report dump")
        )

    def test_new_open_ports_are_grouped_by_port(self):
        """Newly opened ports summarize numerically sorted affected hosts."""
        markdown = build_report_markdown(
            REPORT,
            {"results": {}},
            {},
            {},
            None,
            None,
            new_open_ports={
                "192.0.2.20": ["443", "80"],
                "192.0.2.3": ["80"],
                "192.0.2.10": ["443"],
            },
        )

        section = markdown.split("## New opened port", 1)[1].split(
            "## Full report dump", 1
        )[0]
        self.assertIn(
            "This section summarizes the total number of hosts exposing each open "
            "port during the report period.",
            markdown,
        )
        self.assertIn(
            "Ports newly observed as open during this report period, compared with "
            "the preceding equivalent period.",
            section,
        )
        self.assertIn("- **80**\n  - 192.0.2.3\n  - 192.0.2.20", section)
        self.assertIn("- **443**\n  - 192.0.2.10\n  - 192.0.2.20", section)
        self.assertLess(section.index("- **80**"), section.index("- **443**"))
        self.assertNotIn("New ports:", section)

    def test_report_title_is_a_top_level_heading(self):
        """Generated reports identify their scope in a top-level heading."""
        markdown = build_report_markdown(REPORT, {"results": {}}, {}, {}, None, None)

        self.assertTrue(markdown.startswith("# Report for Protocol report.\n"))
        self.assertNotIn("- Title:", markdown)

    def test_report_description_repeating_query_is_omitted(self):
        """The query must not be repeated above the report heading."""
        report = SimpleNamespace(
            name="domain circl",
            description="domain:circl.lu",
            query="domain:circl.lu",
            schedule_type="monthly",
        )
        markdown = build_report_markdown(report, {"results": {}}, {}, {}, None, None)

        self.assertTrue(markdown.startswith("# Report for Domain circl.\n"))
        self.assertEqual(markdown.count("domain:circl.lu"), 1)
        self.assertLess(
            markdown.index("# Report for Domain circl."), markdown.index("- Query:")
        )

    def test_report_heading_uppercases_user_title_first_character(self):
        """Report heading normalizes the first character of the configured title."""
        report = SimpleNamespace(
            name="domain circl",
            description="",
            query="port:443",
            schedule_type="monthly",
        )
        markdown = build_report_markdown(report, {"results": {}}, {}, {}, None, None)
        self.assertTrue(markdown.startswith("# Report for Domain circl.\n"))

    def test_html_renderer_escapes_content_and_adds_index_anchors(self):
        """Rendered HTML keeps report text inert and headings navigable."""
        html = render_report_markdown_html(
            "# <script>alert(1)</script>\n\n"
            "## Summary\n\n"
            "- Host: <img src=x onerror=alert(1)>\n"
            "  - Query: `port:<script>`\n\n"
            "## Summary\n"
        )

        self.assertIn('<h1 id="script-alert-1-script">', html)
        self.assertIn('<h2 id="summary">Summary</h2>', html)
        self.assertIn('<h2 id="summary-2">Summary</h2>', html)
        self.assertIn('href="#summary"', html)
        self.assertIn('href="#summary-2"', html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertIn("<code>port:&lt;script&gt;</code>", html)
        self.assertIn("<strong>bold</strong>", render_report_markdown_html("**bold**"))
        self.assertIn(
            "Tag: <code>product:nginx</code> <code>proto:http</code>",
            render_report_markdown_html("- Tag: product:nginx, proto:http"),
        )
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img ", html)
        self.assertIn("<ul><li>Host:", html)
        self.assertIn("<ul><li>Query:", html)

        ordered_html = render_report_markdown_html(
            "# Report for Domain circl.\n\n- Query: `domain:circl.lu`\n"
            "- Matching IPs: 77\n\n## Open ports\n"
        )
        self.assertLess(
            ordered_html.index("Report for Domain circl"),
            ordered_html.index("Query:"),
        )
        self.assertLess(ordered_html.index("Query:"), ordered_html.index("<nav"))
        self.assertLess(ordered_html.index("<nav"), ordered_html.index("Open ports"))

    @patch("app.utils.reports.smtplib.SMTP")
    def test_email_contains_markdown_and_html_alternative(self, smtp_class):
        """Report mail retains Markdown fallback alongside escaped HTML."""
        report = SimpleNamespace(
            name="Unsafe <report>", emails_list=lambda: ["analyst@example.test"]
        )
        markdown = "# Unsafe <report>\n\n## Summary\n\n- `port:443`"
        send_report_markdown(
            {"REPORT_SMTP_HOST": "smtp.example.test"}, report, markdown
        )

        message = smtp_class.return_value.__enter__.return_value.send_message.call_args[
            0
        ][0]
        self.assertTrue(message.is_multipart())
        self.assertEqual(message.get_body(("plain",)).get_content().strip(), markdown)
        html = message.get_body(("html",)).get_content()
        self.assertIn('<h1 id="unsafe-report">Unsafe &lt;report&gt;</h1>', html)
        self.assertIn('href="#summary"', html)

    def test_preview_template_has_print_control_and_rendered_html(self):
        """Preview template prints rendered output while hiding controls."""
        template = (ROOT_DIR / "webapp/app/templates/report_preview.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("{{ report_html }}", template)
        self.assertIn("window.print()", template)
        self.assertIn("@media print", template)
        self.assertIn(".report-preview-toolbar", template)

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
