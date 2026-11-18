"""Tag-rule header links sort SQL results while retaining filters and paging."""

from datetime import datetime
from html import unescape
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import app, appbuilder
from app.models import TagRules
from app.views import TagRulesView

TEMPLATES = Path(__file__).resolve().parents[1] / "webapp/app/templates"
LIST_URL = "/tagrulesview/list/"


class TagRulesSortingTest(unittest.TestCase):
    """Exercise the registered list route against a disposable rule database."""

    def setUp(self):
        """Keep test rules and permission overrides away from application data."""
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        TagRules.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        self.addCleanup(session.close)
        for name, day in (("Gamma", 3), ("Alpha", 5), ("Delta", 1), ("Beta", 4)):
            session.add(
                TagRules(
                    name=name,
                    description="Sort fixture",
                    query="port:443",
                    updated_at=datetime(2026, 1, day),
                )
            )
        session.add(
            TagRules(
                name="Excluded",
                description='Other <script> & "tooltip"',
                query="port:22",
                updated_at=datetime(2026, 1, 2),
            )
        )
        session.commit()
        view = next(v for v in appbuilder.baseviews if isinstance(v, TagRulesView))
        self.enterContext(patch.object(view.datamodel, "session", session))
        self.enterContext(patch.object(appbuilder.sm, "has_access", return_value=True))
        self.client = app.test_client()
        self.addCleanup(app.jinja_env.cache.clear)

    def read_page(self, url):
        """Require the real list route to render successfully."""
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    @staticmethod
    def rule_names(page):
        """Extract fixture rows without matching navigation or search labels."""
        return re.findall(r'<span title="Sort fixture">([^<]+)</span>', page)

    def sort_link(self, page, label):
        """Read the header URL emitted by Flask-AppBuilder's actual template."""
        match = re.search(r"<th><a href=([^ >]+)>" + label + r"\s*<i", page)
        self.assertIsNotNone(match, label)
        return unescape(match.group(1).strip('"'))

    def test_sort_links_toggle_database_order_in_all_themes(self):
        """Follow both column links; filters and the second page must survive."""
        for theme in ("plum.css", "readable.css", "flatly.css"):
            loader = FileSystemLoader(TEMPLATES)
            base = "appbuilder/baselayout.html"
            if theme == "plum.css":
                loader = ChoiceLoader(
                    [FileSystemLoader(TEMPLATES / "themes/plum"), loader]
                )
                base = "plum_baselayout.html"
            with (
                self.subTest(theme=theme),
                patch.dict(app.config, APP_THEME=theme),
                patch.object(app, "jinja_loader", loader),
                patch.object(appbuilder, "base_template", base),
            ):
                app.jinja_env.cache.clear()
                params = {
                    "_flt_0_description": "Sort fixture",
                    "psize_TagRulesView": "2",
                    "page_TagRulesView": "1",
                }
                page = self.read_page(LIST_URL + "?" + urlencode(params))
                # Default remains newest first, including the second page.
                self.assertEqual(self.rule_names(page), ["Gamma", "Delta"])
                self.assertIn("js/tag_reconciliation.js", page)
                self.assertEqual(
                    "themes/plum/color_mode.js" in page, theme == "plum.css"
                )
                for case in (
                    ("Rule Name", "name_html", ["Delta", "Gamma"], ["Beta", "Alpha"]),
                    (
                        "Updated",
                        "updated_at_html",
                        ["Beta", "Alpha"],
                        ["Gamma", "Delta"],
                    ),
                ):
                    self.assert_sort_toggle(page, params, case)

    def assert_sort_toggle(self, page, params, case):
        """Follow generated links and verify data, direction, filters and paging."""
        label, column, ascending, descending = case
        for direction, expected in (("asc", ascending), ("desc", descending)):
            link = self.sort_link(page, label)
            args = parse_qs(urlsplit(link).query)
            self.assertEqual(args["_oc_TagRulesView"], [column])
            self.assertEqual(args["_od_TagRulesView"], [direction])
            for key, value in params.items():
                self.assertEqual(args[key], [value])
            page = self.read_page(link)
            self.assertEqual(self.rule_names(page), expected)
            self.assertNotIn(">Excluded</span>", page)
            self.assertIn(
                "fa-chevron-up" if direction == "asc" else "fa-chevron-down", page
            )

    def test_sortable_name_keeps_html_escaped(self):
        """Ordering metadata must preserve safe names and description tooltips."""
        rule = TagRules(name="<b>Rule</b>", description='" onmouseover="alert(1)')
        self.assertEqual(
            str(rule.name_html()),
            '<span title="&quot; onmouseover=&quot;alert(1)">&lt;b&gt;Rule&lt;/b&gt;</span>',
        )
