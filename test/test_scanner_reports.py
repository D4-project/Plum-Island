"""HTTP headers come from observed response lines, never a port number."""

import unittest
from copy import deepcopy

from app.utils.scanner_reports import http_headers_output, normalize_masscan_port
from nmap2json.smarthash import port_smart_hash


class ScannerReportsTest(unittest.TestCase):
    """Regression checks for scanner reports test."""

    def test_full_banner_and_headers_are_added_once_before_hash(self):
        """Verify full banner and headers are added once before hash."""
        output = r"HTTP/1.0 308 Permanent Redirect\x0d\x0aConnection: close\x0d\x0aLocation: https:///\x0d\x0aServer: Caddy\x0d\x0aDate: Sat, 21 Nov 2026 12:22:23 GMT\x0d\x0aContent-Length: 0\x0d\x0a\x0d"
        port = {
            "portid": "80",
            "protocol": "tcp",
            "scripts": [
                {"id": "masscan-detection", "service": "http", "output": output}
            ],
        }
        before = deepcopy(port)
        normalized = normalize_masscan_port(port)
        scripts = {script["id"]: script for script in normalized["scripts"]}
        self.assertEqual(scripts["banner"]["output"], output)
        self.assertIn("Server: Caddy", scripts["http-headers"]["output"])
        self.assertEqual(normalize_masscan_port(normalized), normalized)
        self.assertEqual(port, before)
        changed = deepcopy(port)
        changed["scripts"][0]["output"] = output.replace("12:22:23", "13:42:45")
        self.assertEqual(
            port_smart_hash(normalized),
            port_smart_hash(normalize_masscan_port(changed)),
        )

    def test_observed_headers_keep_duplicates_and_exclude_body(self):
        """Verify observed headers keep duplicates and exclude body."""
        for separator in ("\r\n", r"\x0d\x0a", r"\x0D\x0A"):
            response = separator.join(
                (
                    "HTTP/1.0 308 Permanent Redirect",
                    "Server: Caddy",
                    "Date: Sat, 21 Nov 2026 12:22:23 GMT",
                    "Set-Cookie: a=1",
                    "Set-Cookie: b=2",
                    "",
                    "<html>body</html>",
                )
            )
            self.assertEqual(
                http_headers_output(response),
                "\nServer: Caddy\nDate: Sat, 21 Nov 2026 12:22:23 GMT\nSet-Cookie: a=1\nSet-Cookie: b=2",
            )

    def test_non_http_and_incomplete_headers_are_not_invented(self):
        """Verify non http and incomplete headers are not invented."""
        for response in (
            "SSH-2.0-OpenSSH",
            " ALERT(0x0246) ",
            "HTTP/1.1 200 OK",
            "HTTP/1.1 200 OK\r\nServ...",
        ):
            self.assertIsNone(http_headers_output(response))

    def test_existing_nmap_fields_are_preserved(self):
        """Verify existing nmap fields are preserved."""
        port = {
            "scripts": [
                {
                    "id": "masscan-detection",
                    "output": "HTTP/1.1 200 OK\r\nServer: observed\r\n\r\n",
                },
                {"id": "banner", "output": "existing banner"},
                {"id": "http-headers", "output": "existing headers"},
            ]
        }
        scripts = {
            item["id"]: item["output"]
            for item in normalize_masscan_port(port)["scripts"]
        }
        self.assertEqual(scripts["banner"], "existing banner")
        self.assertEqual(scripts["http-headers"], "existing headers")
