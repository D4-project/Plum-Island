"""Verify the parser-derived completion catalogue and both browser templates."""

import ast
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from test.test_kvrocks_search import isolated_search_view, make_indexer
from types import SimpleNamespace
from unittest.mock import Mock, patch

from jinja2 import Environment

# pylint: disable=protected-access,missing-function-docstring

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "webapp/app/templates"


def isolated_view():
    """Load real catalogue and rendering methods without application startup."""
    tree = ast.parse((ROOT / "webapp/app/views.py").read_text())
    view = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "KVSearchView"
    )
    view.bases = []
    view.body = [
        node
        for node in view.body
        if (
            isinstance(node, ast.FunctionDef)
            and node.name
            in {"search_keywords", "_search_suggestion_keywords", "search"}
        )
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "SINCE_PREFIX"
                for target in node.targets
            )
        )
    ]
    for node in view.body:
        if isinstance(node, ast.FunctionDef) and node.name == "search":
            node.decorator_list = []
    namespace = {
        "KVrocksIndexer": lambda *_args: SimpleNamespace(
            objects_count=lambda: {"uid_count": 5}
        ),
        "db": SimpleNamespace(
            app=SimpleNamespace(config={"KVROCKS_HOST": "unused", "KVROCKS_PORT": 0})
        ),
        "RedisError": RuntimeError,
    }
    module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
    exec(  # pylint: disable=exec-used
        compile(module, "<isolated keyword catalogue>", "exec"), namespace
    )
    result = namespace["KVSearchView"]()
    return result


class SearchKeywordAutocompleteTest(unittest.TestCase):
    """Keep suggestions aligned with parser fields, safe and backend-independent."""

    def setUp(self):
        self.view = isolated_view()

    def test_catalogue_contains_only_parser_fields_and_special_directives(self):
        self.assertEqual(
            self.view._search_suggestion_keywords(),
            sorted(set(self.view.search_keywords()) | {"http_headval", "since"}),
        )
        with patch.object(self.view.__class__, "search_keywords", return_value=["new"]):
            self.assertEqual(
                self.view._search_suggestion_keywords(),
                ["http_headval", "new", "since"],
            )

    def test_search_page_receives_catalogue_even_if_tag_catalogue_is_unavailable(self):
        self.view.render_template = Mock(return_value="page")
        self.view._collect_tag_catalogue = Mock(return_value=[])
        for failure in (None, RuntimeError("tag backend unavailable")):
            self.view._collect_tag_catalogue.side_effect = failure
            self.assertEqual(self.view.search(), "page")
            args, data = self.view.render_template.call_args
            self.assertEqual(args, ("search_kvrocks.html",))
            self.assertEqual(
                data["search_keywords"], self.view._search_suggestion_keywords()
            )
            self.assertEqual(data["tag_catalogue_error"], failure is not None)
            self.assertEqual(data["total_scan_count"], 5)

    def test_both_templates_embed_json_with_script_safe_escaping(self):
        fields = self.view._search_suggestion_keywords() + [
            '</script><img onerror="x">'
        ]
        for name in ("search_kvrocks.html", "themes/plum/search_kvrocks.html"):
            with self.subTest(template=name):
                source = (TEMPLATES / name).read_text()
                self.assertIn("{% include 'search_query_helpers.html' %}", source)
                shared = (TEMPLATES / "search_query_helpers.html").read_text()
                self.assertIn("filename='js/search_autocomplete.js'", shared)
                self.assertIn('nonce="{{ baselib.get_nonce() }}"', shared)
                script = re.search(
                    r'<script type="application/json" id="search-keywords">(.*?)</script>',
                    shared,
                    re.DOTALL,
                )
                self.assertIsNotNone(script)
                rendered = (
                    Environment(autoescape=True)
                    .from_string(script[1])
                    .render(search_keywords=fields)
                )
                self.assertEqual(json.loads(rendered), fields)
                self.assertNotIn("</script>", rendered)

    @unittest.skipUnless(shutil.which("node"), "Node.js required for UI checks")
    def test_browser_completion_uses_real_catalogue_in_both_themes(self):
        for theme in ("original", "plum"):
            with self.subTest(theme=theme):
                subprocess.run(
                    [shutil.which("node"), str(ROOT / "test/search_keyword_ui.js")],
                    env=dict(
                        os.environ,
                        PLUM_TEST_THEME=theme,
                        PLUM_SEARCH_KEYWORDS=json.dumps(
                            self.view._search_suggestion_keywords()
                        ),
                    ),
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )

    def test_all_example_queries_are_accepted_by_the_real_parser(self):
        view = isolated_search_view(make_indexer())
        source = (TEMPLATES / "search_query_examples.html").read_text()
        queries = re.findall(r'data-query-example="([^"]+)"', source)
        self.assertEqual(len(queries), 7)
        for query in queries:
            with self.subTest(query=query):
                _, valid, error = view.parse_query(query)
                self.assertTrue(valid, error)

    def test_modifier_examples_demonstrate_prefix_versus_substring(self):
        indexer = make_indexer(
            {
                "http_server:nginx/1.26": {"prefix"},
                "http_server:custom-nginx": {"substring"},
                "http_server:apache": {"other"},
            }
        )
        for modifier, expected in (
            ("bg", {"prefix"}),
            ("begin", {"prefix"}),
            ("lk", {"prefix", "substring"}),
            ("like", {"prefix", "substring"}),
        ):
            with self.subTest(modifier=modifier):
                self.assertEqual(
                    set(
                        indexer.get_uids_by_criteria(
                            {f"http_server.{modifier}": ["nginx"]}
                        )
                    ),
                    expected,
                )

    def test_suggested_field_modifiers_are_accepted_by_parser(self):
        view = isolated_search_view(make_indexer())
        for field in self.view.search_keywords():
            if field in {"tag", "engine", "nodata"}:
                continue
            for modifier in ("bg", "begin", "lk", "like"):
                with self.subTest(field=field, modifier=modifier):
                    _, valid, error = view.parse_query(f"{field}.{modifier}:nginx")
                    self.assertTrue(valid, error)
