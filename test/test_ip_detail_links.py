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

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader
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

    @staticmethod
    def _detail_fixture():
        """Load the actual view with fake storage, without app startup."""
        indexer = make_indexer(
            {
                "ip:8.8.8.8": {"old", "new"},
                "tags:old": {"proto:http"},
                "tags:new": {"product:nginx", "vendor:nginx"},
            }
        )
        documents = {}
        fetched = []
        for number in range(1000):
            uid = f"other-{number}"
            indexer.r.sets["ip:8.8.8.8"].add(uid)
            indexer.r.sets[f"fqdn_requesteds:{uid}"] = {"new.example.org"}
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
            indexer.r.sets[f"fqdn_requesteds:{uid}"] = {host}

        def load_document(_index, uid):
            fetched.append(uid)
            return documents[uid], False, None

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
            "KVSearchView": SimpleNamespace(load_meili_document=load_document),
            "request": SimpleNamespace(args={"hostname": "OLD.example.org"}),
            "make_response": lambda message, status: (message, status),
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
        return instance, indexer, documents, namespace, fetched

    def test_detail_keeps_tag_and_tls_decisions_per_observation(self):
        """Only selected reports are loaded; per-observation tags remain intact."""
        instance, indexer, documents, namespace, fetched = self._detail_fixture()
        context = instance.detail("8.8.8.8")
        cards = {card["portid"]: card for card in context["port_cards"]}
        self.assertEqual(
            [item["web_scheme"] for item in cards["8443"]["observations"]],
            ["https"],
        )
        self.assertEqual(
            [item["web_scheme"] for item in cards["8080"]["observations"]], ["http"]
        )
        self.assertEqual(
            context["requested_hostnames"], ["new.example.org", "old.example.org"]
        )
        self.assertEqual(context["ip_tags"], ["proto:http"])
        self.assertEqual(
            [item["last_seen_epoch"] for item in cards["8443"]["observations"]],
            [200],
        )
        self.assertEqual(cards["8443"]["observations"][0]["first_seen_epoch"], 200)
        self.assertEqual(fetched, ["old"])
        self.assertEqual(context["total_documents"], 1)
        namespace["request"].args = {"hostname": "new.example.org"}
        # Only the metadata catalogue is read for unrelated histories.
        # Remove the synthetic history before visiting its group.
        indexer.r.sets["ip:8.8.8.8"] = {"old", "new"}
        context = instance.detail("8.8.8.8")
        self.assertEqual(fetched, ["old", "new"])
        self.assertEqual(context["ip_tags"], ["product:nginx", "vendor:nginx"])
        self.assertTrue(
            all(
                observation["web_scheme"] == ""
                for card in context["port_cards"]
                for observation in card["observations"]
            )
        )
        namespace["request"].args = {}
        context = instance.detail("8.8.8.8")
        self.assertEqual(context["port_cards"], [])
        self.assertEqual(context["total_documents"], 0)
        self.assertEqual(fetched, ["old", "new"])
        namespace["request"].args = {"hostname": "unrelated.example.org"}
        self.assertEqual(instance.detail("8.8.8.8")[1], 404)
        self.assertEqual(fetched, ["old", "new"])

        indexer.r.sets["ip:8.8.8.8"].add("ip-only")
        documents["ip-only"] = {
            "body": {"ports": [{"protocol": "tcp", "portid": "22"}]}
        }
        namespace["request"].args = {}
        context = instance.detail("8.8.8.8")
        self.assertEqual(fetched[-1], "ip-only")
        self.assertEqual(context["total_documents"], 1)
        self.assertEqual(context["port_cards"][0]["portid"], "22")

        namespace["KVSearchView"].load_meili_document = lambda _index, uid: (
            None,
            True,
            f"Missing document {uid}",
        )
        context = instance.detail("8.8.8.8")
        self.assertEqual(context["port_cards"], [])
        self.assertEqual(context["unmapped_documents"][0]["uid"], "ip-only")

    def test_fragment_is_scoped_escaped_and_without_page_scripts(self):
        """Both HTTP forms reuse the same static blocks, with autoescaping."""
        environment = Environment(
            loader=ChoiceLoader(
                [
                    DictLoader(
                        {
                            "appbuilder/base.html": "{% block content %}{% endblock %}",
                            "appbuilder/general/lib.html": (
                                "{% macro panel_begin(a,b) %}{% endmacro %}"
                                "{% macro panel_end() %}{% endmacro %}"
                            ),
                        }
                    ),
                    FileSystemLoader(ROOT / "webapp/app/templates"),
                ]
            ),
            autoescape=True,
        )
        environment.globals.update(
            baselib=SimpleNamespace(get_nonce=lambda: ""),
            url_for=lambda *_args, **_kwargs: "/unused",
        )
        values = {
            "ip": "2001:db8::1",
            "selected_hostname": "example.org",
            "requested_hostnames": ["example.org"],
            "ip_tags": ["product:<script>"],
            "total_documents": 1,
            "total_ports": 0,
            "port_cards": [],
            "warnings": ["<script>alert(1)</script>"],
            "unmapped_documents": [],
        }
        template = environment.get_template("ip_detail.html")
        fragment = template.render(fragment=True, **values)
        self.assertIn('id="ip-scan-group"', fragment)
        self.assertIn('id="ip-scan-summary"', fragment)
        self.assertIn("&lt;script&gt;", fragment)
        self.assertNotIn("<script", fragment)
        self.assertNotIn('id="ip-whois"', fragment)
        full = template.render(fragment=False, **values)
        self.assertEqual(full.count('id="ip-scan-group"'), 1)
        self.assertEqual(full.count('id="ip-scan-summary"'), 1)
        self.assertIn('value="example.org" selected', full)
        self.assertIn('id="ip-whois"', full)

    @unittest.skipUnless(shutil.which("node"), "Node.js required for cache checks")
    def test_hostname_cache(self):
        """Cached groups and stale replies cannot override the current selection."""
        subprocess.run(
            [
                shutil.which("node"),
                str(Path(__file__).with_name("ip_hostname_groups_ui.js")),
            ],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
        )

    @unittest.skipUnless(shutil.which("node"), "Node.js required for timeline checks")
    def test_port_timelines(self):
        """Exercise shared-scale layout and DOM interactions without backends."""
        subprocess.run(
            [
                shutil.which("node"),
                str(Path(__file__).with_name("ip_port_timeline_ui.js")),
            ],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
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
