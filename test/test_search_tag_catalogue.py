"""Observed tag catalogue, bounded refreshes and safe search helper rendering."""

# pylint: disable=protected-access

import inspect
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from redis.exceptions import ConnectionError as KvrocksConnectionError

from app import app, db
from app.views import KVSearchView


class SearchTagCatalogueTest(unittest.TestCase):
    """Exercise the real view helpers without live search backends or databases."""

    def setUp(self):
        """Keep process-local cache state isolated across tests."""
        self.enterContext(patch.object(KVSearchView, "_tag_catalogue_cache", None))

    def test_observed_tags_are_sorted_and_grouped_without_sql(self):
        """Only observed tags feed the five columns, independent of SQL rules."""
        with patch("app.views.KVrocksIndexer") as indexer, patch.object(
            KVSearchView, "_collect_rule_tags", side_effect=AssertionError("SQL read")
        ):
            indexer.return_value.get_observed_tags.return_value = [
                "product:zulu",
                "proto:ssh",
                "product:apache",
                "type:firewall",
                "vendor:ovh",
                "vuln:cve-2025-1234",
                "lang:php",
                "proto:ssh",
            ]
            columns = KVSearchView._collect_tag_catalogue()
            self.assertEqual(
                [c["label"] for c in columns],
                ["Proto", "Type", "Products", "Vendors", "Vulns"],
            )
            self.assertEqual(
                [[t["label"] for t in c["tags"]] for c in columns],
                [
                    ["proto:ssh"],
                    ["type:firewall"],
                    ["product:apache", "product:zulu"],
                    ["vendor:ovh"],
                    ["vuln:cve-2025-1234"],
                ],
            )
            self.assertTrue(
                all(
                    t["term"] == "tag:" + t["label"] for c in columns for t in c["tags"]
                )
            )
            indexer.return_value.get_observed_tags.assert_called_once()

    def test_cache_expires_and_backend_changes_refresh(self):
        """Repeated loads reuse results; expiry and backend changes refresh them."""
        with patch("app.views.KVrocksIndexer") as indexer, patch(
            "app.views.time.monotonic", return_value=100
        ) as clock:
            indexer.return_value.get_observed_tags.return_value = ["proto:ssh"]
            KVSearchView._collect_tag_catalogue()
            clock.return_value = 159
            KVSearchView._collect_tag_catalogue()
            indexer.return_value.get_observed_tags.assert_called_once()
            clock.return_value = 160
            indexer.return_value.get_observed_tags.return_value = []
            columns = KVSearchView._collect_tag_catalogue()
            self.assertFalse(any(column["tags"] for column in columns))
            self.assertEqual(indexer.return_value.get_observed_tags.call_count, 2)
            with patch.dict(db.app.config, {"KVROCKS_HOST": "different-backend"}):
                KVSearchView._collect_tag_catalogue()
            self.assertEqual(indexer.return_value.get_observed_tags.call_count, 3)

    def test_template_escapes_labels_and_handles_empty_catalogue(self):
        """Indexed text is data, including quotes inside HTML attributes."""
        with patch("app.views.KVrocksIndexer") as indexer:
            indexer.return_value.get_observed_tags.return_value = []
            columns = KVSearchView._collect_tag_catalogue()
        template = app.jinja_env.get_template("search_tag_catalogue.html")
        html = template.render(tag_catalogue=columns, tag_catalogue_error=False)
        self.assertEqual(html.count("No tags"), 5)
        self.assertEqual(html.count('scope="col"'), 5)
        columns[0]["tags"] = [
            {"label": "<script>alert(1)</script>", "term": 'tag:proto:" onclick="bad'}
        ]
        html = template.render(tag_catalogue=columns, tag_catalogue_error=False)
        self.assertNotIn("<script>", html)
        self.assertNotIn(' onclick="bad', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&#34;", html)

    def test_kvrocks_catalogue_failure_preserves_search_page(self):
        """A catalogue failure still renders search controls and keyword help."""
        view = KVSearchView()
        with app.test_request_context("/kvsearchview/search"), patch(
            "app.views.KVrocksIndexer"
        ) as indexer, patch.object(
            view, "_collect_tag_catalogue", side_effect=KvrocksConnectionError()
        ), patch.object(
            view, "render_template", return_value="page"
        ) as render, patch.object(
            db.session, "rollback"
        ) as rollback:
            indexer.return_value.objects_count.return_value = {"uid_count": 10}
            self.assertEqual(inspect.unwrap(KVSearchView.search)(view), "page")
            self.assertTrue(render.call_args.kwargs["tag_catalogue_error"])
            self.assertEqual(render.call_args.kwargs["total_scan_count"], 10)
            rollback.assert_not_called()

    @unittest.skipUnless(shutil.which("node"), "Node.js required for UI checks")
    def test_browser_helpers(self):
        """All namespaces append terms and toggling preserves query text."""
        subprocess.run(
            [
                shutil.which("node"),
                str(Path(__file__).with_name("search_keyword_ui.js")),
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
