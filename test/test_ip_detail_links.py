"""Check tag-driven IP page links without querying external services."""

import ast
import logging
import shutil
import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from test.test_kvrocks_search import make_indexer
from ip_links import port_web_scheme
from tagrules import normalize_tags

ROOT = Path(__file__).resolve().parents[1]


class IpDetailLinksTest(unittest.TestCase):
    """Use this observation's HTTP tag and this port's TLS evidence."""

    def test_schemes_require_http_tag_and_use_port_tls_evidence(self):
        """Service names alone must not create links on untagged observations."""
        for port in (
            {"portid": "80", "service": {"name": "http"}},
            {"portid": "443", "service": {"name": "https"}},
            {"portid": "8443", "scripts": [{"id": "ssl-cert"}]},
        ):
            self.assertEqual(port_web_scheme(port, []), "")
            self.assertEqual(port_web_scheme(port, ["proto:ssh"]), "")
        for service in (
            {"name": "https"},
            {"name": "https-alt"},
            {"name": "ssl"},
            {"name": "ssl/http"},
            {"name": "http", "tunnel": "SSL"},
            {"name": "unknown", "tunnel": "tls"},
        ):
            with self.subTest(service=service):
                self.assertEqual(
                    port_web_scheme(
                        {"portid": "8443", "service": service}, ["proto:http"]
                    ),
                    "https",
                )
        self.assertEqual(
            port_web_scheme({"scripts": [{"id": "ssl-cert"}]}, ["proto:http"]), "https"
        )
        self.assertEqual(
            port_web_scheme(
                {"portid": "8080", "service": {"name": "unknown"}}, ["proto:http"]
            ),
            "http",
        )
        # Port 443 alone does not override actual plain HTTP evidence.
        self.assertEqual(
            port_web_scheme(
                {"portid": "443", "service": {"name": "http"}}, ["proto:http"]
            ),
            "http",
        )

    def test_detail_keeps_tag_and_tls_decisions_per_observation(self):
        """Execute the actual view with fake storage, without app startup."""
        indexer = make_indexer(
            {
                "ip:8.8.8.8": {"old", "new"},
                "tags:old": {"proto:http"},
                "tags:new": {"product:nginx", "vendor:nginx"},
            }
        )
        documents = {}
        for uid, timestamp, service, host in (
            ("old", 200, {"name": "http", "tunnel": "ssl"}, "old.example.org"),
            ("new", 300, {"name": "https"}, "new.example.org"),
        ):
            indexer.r.hashes[f"doc:{uid}"] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
            documents[uid] = {
                "body": {
                    "hostnames": [{"type": "user", "name": host}],
                    "ports": [
                        {"portid": "8443", "protocol": "tcp", "service": service},
                        {
                            "portid": "8080",
                            "protocol": "tcp",
                            "service": {"name": "unknown"},
                        },
                    ],
                }
            }

        tree = ast.parse((ROOT / "webapp/app/views.py").read_text())
        view = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "IPDetailView"
        )
        view.bases = []
        view.body = [
            node
            for node in view.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            in {
                "detail",
                "_safe_timestamp_to_display",
                "_port_group_sort_key",
                "_extract_hostname_details",
            }
        ]
        for node in view.body:
            if node.name == "detail":
                node.decorator_list = []  # Auth is outside this isolated view test.
        namespace = {
            "datetime": datetime,
            "timezone": timezone,
            "is_valid_ip": lambda ip: ip == "8.8.8.8",
            "KVrocksIndexer": lambda *_args: indexer,
            "KVSearchView": SimpleNamespace(
                load_meili_document=lambda _index, uid: (documents[uid], False, None)
            ),
            "client": SimpleNamespace(index=lambda _name: None),
            "db": SimpleNamespace(
                app=SimpleNamespace(
                    config={"KVROCKS_HOST": "unused", "KVROCKS_PORT": 0}
                )
            ),
            "normalize_tags": normalize_tags,
            "port_web_scheme": port_web_scheme,
            "logger": logging.getLogger(__name__),
        }
        module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
        exec(  # pylint: disable=exec-used
            compile(module, "<isolated IPDetailView>", "exec"), namespace
        )
        instance = namespace["IPDetailView"]()
        instance.render_template = lambda _name, **context: context
        context = instance.detail("8.8.8.8")
        cards = {card["portid"]: card for card in context["port_cards"]}
        self.assertEqual(
            [item["web_scheme"] for item in cards["8443"]["observations"]],
            ["https", ""],
        )
        self.assertEqual(
            [item["web_scheme"] for item in cards["8080"]["observations"]], ["http", ""]
        )
        self.assertEqual(
            context["requested_hostnames"], ["new.example.org", "old.example.org"]
        )
        self.assertEqual(
            context["ip_tags"], ["product:nginx", "proto:http", "vendor:nginx"]
        )

    @unittest.skipUnless(shutil.which("node"), "Node.js required for IP link checks")
    def test_browser_links(self):
        """Check actual JS URL builders and observation switching."""
        subprocess.run(
            [
                shutil.which("node"),
                str(Path(__file__).with_name("ip_detail_links_ui.js")),
            ],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
