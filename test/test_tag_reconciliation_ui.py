"""Shared automatic progress, without a manual update action, in every theme."""

from pathlib import Path
import shutil
import subprocess
import unittest

from flask import Flask
from jinja2 import ChoiceLoader, DictLoader

from app.ui_theme import configure_ui_templates

ROOT = Path(__file__).resolve().parents[1]


class ReconciliationUiTest(unittest.TestCase):
    """Render real templates and execute the shared progress controller."""

    def test_progress_is_shared_and_update_buttons_are_removed(self):
        """Plum, Readable and Flatly render the same passive progress controls."""
        for theme in ("plum.css", "readable.css", "flatly.css"):
            with self.subTest(theme=theme):
                app = Flask("reconciliation-ui", root_path=str(ROOT / "webapp/app"))
                app.config["APP_THEME"] = theme
                configure_ui_templates(app)
                app.jinja_loader = ChoiceLoader(
                    [
                        DictLoader(
                            {
                                "appbuilder/general/model/list.html": "{% block head_css %}{% endblock %}"
                                "{% block content %}{% block list_list %}{% endblock %}{% endblock %}"
                                "{% block tail_js %}{% endblock %}",
                            }
                        ),
                        app.jinja_loader,
                    ]
                )
                app.jinja_env.globals["url_for"] = (
                    lambda endpoint, **values: values.get("filename", endpoint)
                )
                rendered = app.jinja_env.get_template("list_tagrulesview.html").render()
                self.assertIn("data-index-progress", rendered)
                self.assertIn('role="progressbar"', rendered)
                self.assertIn("js/tag_reconciliation.js", rendered)
                self.assertNotIn("<button", rendered)
                self.assertNotIn("reindex_start", rendered)

    @unittest.skipUnless(
        shutil.which("node"), "Node is required for browser-script checks"
    )
    def test_progress_counts_indeterminate_phases_and_safe_text(self):
        """Run the real JS controller through planning, work, failure and completion."""
        result = subprocess.run(
            [shutil.which("node"), str(ROOT / "test/tag_reconciliation_ui.js")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
