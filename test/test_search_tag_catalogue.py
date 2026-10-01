"""SQL-only tag catalogue and safe search helper rendering."""

# pylint: disable=protected-access

import inspect
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app import app, db
from app.models import TagRules
from app.views import KVSearchView


class SearchTagCatalogueTest(unittest.TestCase):
    """Exercise the real view helpers without live search backends or databases."""

    def test_active_sql_rules_are_deduplicated_sorted_and_grouped(self):
        """Catalogue uses active rules, not tags observed in indexed documents."""
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        TagRules.__table__.create(engine)
        with sessionmaker(bind=engine)() as session, patch.object(
            db, "session", session
        ), patch("app.views.KVrocksIndexer") as indexer:
            session.add_all(
                [
                    TagRules(
                        name="one",
                        description="test",
                        query="port:443",
                        tags="proto:ssh,product:zulu,type:firewall,vendor:ovh,vuln:cve-2025-1234",
                        active=True,
                    ),
                    TagRules(
                        name="two",
                        description="test",
                        query="port:80",
                        tags="proto:ssh\nproduct:apache\nlang:php",
                        active=True,
                    ),
                    TagRules(
                        name="off",
                        description="test",
                        query="port:22",
                        tags="proto:telnet",
                        active=False,
                    ),
                ]
            )
            session.commit()
            columns = (
                KVSearchView._collect_tag_catalogue()
            )  # pylint: disable=protected-access
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
            indexer.assert_not_called()

    def test_template_escapes_labels_and_handles_empty_catalogue(self):
        """SQL text is data, including quotes inside HTML attributes."""
        with patch.object(KVSearchView, "_collect_rule_tags", return_value=[]):
            columns = (
                KVSearchView._collect_tag_catalogue()
            )  # pylint: disable=protected-access
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

    def test_sql_failure_preserves_search_page(self):
        """A catalogue failure still renders search controls and keyword help."""
        view = KVSearchView()
        with app.test_request_context("/kvsearchview/search"), patch(
            "app.views.KVrocksIndexer"
        ) as indexer, patch.object(
            view, "_collect_tag_catalogue", side_effect=SQLAlchemyError()
        ), patch.object(
            view, "render_template", return_value="page"
        ) as render, patch.object(
            db.session, "rollback"
        ) as rollback:
            indexer.return_value.objects_count.return_value = {"uid_count": 10}
            self.assertEqual(inspect.unwrap(KVSearchView.search)(view), "page")
            self.assertTrue(render.call_args.kwargs["tag_catalogue_error"])
            self.assertEqual(render.call_args.kwargs["total_scan_count"], 10)
            rollback.assert_called_once()

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
