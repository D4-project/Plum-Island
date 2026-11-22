"""Verify that the optional Plum UI leaves the original interface available."""

import ast
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless

from flask import Flask
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader, TemplateNotFound

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "plum_ui_theme", ROOT / "webapp/app/ui_theme.py"
)
UI_THEME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UI_THEME)
SCANNER_SPEC = importlib.util.spec_from_file_location(
    "plum_scanner_reports", ROOT / "webapp/app/utils/scanner_reports.py"
)
SCANNER_REPORTS = importlib.util.module_from_spec(SCANNER_SPEC)
SCANNER_SPEC.loader.exec_module(SCANNER_REPORTS)


class UiThemeTest(TestCase):
    """Exercise template selection, inheritance and both UI implementations."""

    def test_new_installation_defaults_to_plum(self):
        """The template copied by standard and container setup selects Plum."""
        source = ast.parse((ROOT / "webapp/config.py.template").read_text())
        themes = [
            ast.literal_eval(node.value)
            for node in source.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "APP_THEME"
                for target in node.targets
            )
        ]
        self.assertEqual(themes, ["plum.css"])

    def test_legacy_plum_config_loads_color_mode_script_in_rendered_page(self):
        """Selecting Plum must load its JS even without FAB_BASE_TEMPLATE in config."""
        framework = Path(importlib.util.find_spec("flask_appbuilder").origin).parent
        for theme in ("plum.css", "readable.css", "flatly.css"):
            with self.subTest(theme=theme):
                app = Flask("theme-script-test", root_path=str(ROOT / "webapp/app"))
                app.config["APP_THEME"] = theme
                UI_THEME.configure_ui_templates(app)
                app.jinja_loader = ChoiceLoader(
                    [
                        DictLoader(
                            {
                                "probe.html": "{% extends 'appbuilder/base.html' %}"
                                "{% block body %}Theme probe{% endblock %}"
                            }
                        ),
                        app.jinja_loader,
                        FileSystemLoader(framework / "templates"),
                    ]
                )
                app.jinja_env.globals["url_for"] = (
                    lambda _endpoint, **values: "/assets/" + values.get("filename", "")
                )
                rendered = app.jinja_env.get_template("probe.html").render(
                    base_template=app.config.get(
                        "FAB_BASE_TEMPLATE", "appbuilder/baselayout.html"
                    ),
                    appbuilder=SimpleNamespace(app_theme=theme, app_name="Theme probe"),
                )
                self.assertEqual(
                    rendered.count('src="/assets/themes/plum/color_mode.js"'),
                    1 if theme == "plum.css" else 0,
                )

    def test_explicit_base_layout_is_preserved(self):
        """Do not overwrite an installation's explicitly customized base template."""
        app = Flask("custom-theme-layout", root_path=str(ROOT / "webapp/app"))
        app.config.update(APP_THEME="plum.css", FAB_BASE_TEMPLATE="custom_layout.html")
        UI_THEME.configure_ui_templates(app)
        self.assertEqual(app.config["FAB_BASE_TEMPLATE"], "custom_layout.html")

    @skipUnless(shutil.which("node"), "Node.js required for UI checks")
    def test_color_mode_preferences(self):
        """Preserve manual choices and synchronize existing and new viewers."""
        subprocess.run(
            [shutil.which("node"), str(ROOT / "test/plum_color_mode_ui.js")],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_template_inheritance_and_fallback_follow_selected_theme(self):
        """Plum overrides includes and parents, falling back to original files."""
        with TemporaryDirectory() as directory:
            templates = Path(directory) / "templates"
            themed = templates / "themes/plum"
            themed.mkdir(parents=True)
            (templates / "base.html").write_text(
                "Original {% block body %}{% endblock %}"
            )
            (templates / "page.html").write_text(
                "{% extends 'base.html' %}{% block body %}"
                "{% include 'part.html' %} {% include 'shared.html' %}{% endblock %}"
            )
            (templates / "part.html").write_text("original part")
            (templates / "shared.html").write_text("shared fallback")
            (themed / "base.html").write_text("Plum {% block body %}{% endblock %}")
            (themed / "part.html").write_text("custom part")
            for theme, expected in (
                ("readable.css", "Original original part shared fallback"),
                ("plum.css", "Plum custom part shared fallback"),
                ("flatly.css", "Original original part shared fallback"),
            ):
                with self.subTest(theme=theme):
                    app = Flask("ui-theme-test", root_path=directory)
                    app.config["APP_THEME"] = theme
                    UI_THEME.configure_ui_templates(app)
                    self.assertEqual(
                        app.jinja_env.get_template("page.html").render(), expected
                    )

    def test_real_template_overrides_are_confined_to_plum(self):
        """Readable resolves original pages and no custom framework navbar."""
        root = ROOT / "webapp/app"
        for theme in ("readable.css", "plum.css"):
            with self.subTest(theme=theme):
                app = Flask("ui-theme-paths", root_path=str(root))
                app.jinja_env.filters["scanner_scripts"] = (
                    SCANNER_REPORTS.display_scripts
                )
                app.config["APP_THEME"] = theme
                UI_THEME.configure_ui_templates(app)
                expected = root / "templates"
                if theme == "plum.css":
                    expected /= "themes/plum"
                for name in (
                    "plum_baselayout.html",
                    "ip_detail.html",
                    "search_kvrocks.html",
                ):
                    template = app.jinja_env.get_template(name)
                    self.assertEqual(Path(template.filename), expected / name)
                if theme == "plum.css":
                    app.jinja_env.get_template("appbuilder/navbar.html")
                else:
                    with self.assertRaises(TemplateNotFound):
                        app.jinja_env.get_template("appbuilder/navbar.html")

    @skipUnless(shutil.which("node"), "Node.js required for UI checks")
    def test_plum_template_interactions(self):
        """Run the same interaction checks against the isolated Plum templates."""
        environment = dict(os.environ, PLUM_TEST_THEME="plum")
        for name in (
            "ip_detail_links_ui.js",
            "ip_hostname_groups_ui.js",
            "ip_port_timeline_ui.js",
            "ip_whois_ui.js",
            "search_debug_ui.js",
            "search_keyword_ui.js",
            "search_resolved_export_ui.js",
            "target_show_results_ui.js",
        ):
            with self.subTest(script=name):
                subprocess.run(
                    [shutil.which("node"), str(ROOT / "test" / name)],
                    env=environment,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
