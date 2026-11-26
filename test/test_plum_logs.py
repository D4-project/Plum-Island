"""Verify log browsing with real FAB roles and isolated files."""

from html import unescape
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from flask import Flask, g
from flask_appbuilder import AppBuilder, SQLA
from flask_login import login_user
from jinja2 import ChoiceLoader, FileSystemLoader

from app import app as island_app
from app import appbuilder as island_appbuilder
from app import logs_view
from app.security import CustomSecurityManager
from app.ui_theme import configure_ui_templates

ROOT = Path(__file__).resolve().parents[1]
URL = "/plumlogs/"


class PlumLogsTest(unittest.TestCase):
    """Use a private database and directory instead of developer logs."""

    def setUp(self):
        directory = self.enterContext(
            TemporaryDirectory()  # pylint: disable=consider-using-with
        )
        self.directory = Path(directory)
        self.logs = self.directory / "log"
        self.logs.mkdir()
        self.app = Flask(__name__, root_path=str(ROOT / "webapp/app"))
        self.app.config.update(
            SECRET_KEY="log-view-fixture",
            SQLALCHEMY_DATABASE_URI="sqlite://",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            AUTH_ROLE_ADMIN="Log Administrators",
            APP_THEME="readable.css",
            LOG_DIR=str(self.logs),
            TESTING=True,
        )
        configure_ui_templates(self.app)
        context = self.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        db = SQLA(self.app)
        self.builder = AppBuilder(
            self.app, db.session, security_manager_class=CustomSecurityManager
        )
        self.addCleanup(db.engine.dispose)
        self.addCleanup(db.session.remove)
        self.builder.add_view(
            logs_view.PlumLogsView,
            "Plum Logs",
            category="Security",
            menu_cond=self.builder.sm.is_plum_admin,
        )
        self.admin = self.builder.sm.add_user(
            "log-admin",
            "Log",
            "Admin",
            "log-admin@example.org",
            self.builder.sm.find_role("Log Administrators"),
            password="fixture-only",
        )
        self.operator = self.builder.sm.add_user(
            "log-operator",
            "Log",
            "Operator",
            "log-operator@example.org",
            self.builder.sm.add_role("Log Operator"),
            password="fixture-only",
        )
        self.client = self.app.test_client()

    def _login(self, user):
        g.pop("_login_user", None)
        with self.client.session_transaction() as session:
            session.update(_user_id=str(user.id), _fresh=True)

    def test_route_is_registered_in_island_security_menu(self):
        """The production entry point registers the same view and menu."""
        self.assertIn("PlumLogsView.index", island_app.view_functions)
        self.assertIsNotNone(island_appbuilder.menu.find("Plum Logs"))

    def test_non_admin_denied_even_with_misassigned_permissions(self):
        """Neither a direct request nor a fabricated grant can expose logs."""
        (self.logs / "island.log").write_text("private log fixture", encoding="utf-8")
        for user in (None, self.operator):
            if user is not None:
                for permission, view in (
                    ("can_index", "PlumLogsView"),
                    ("menu_access", "Plum Logs"),
                    ("menu_access", "Security"),
                ):
                    pair = self.builder.sm.find_permission_view_menu(permission, view)
                    self.builder.sm.add_permission_role(user.roles[0], pair)
                self._login(user)
            with self.subTest(user=user):
                response = self.client.get(URL, query_string={"file": "island.log"})
                self.assertIn(response.status_code, (302, 403))
                self.assertNotIn(b"private log fixture", response.data)
        with self.app.test_request_context():
            login_user(self.operator)
            g.user = self.operator
            self.assertNotIn("Plum Logs", self.builder.sm.get_user_menu_access())
            self.assertFalse(self.builder.menu.find("Plum Logs").should_render())

    def test_latest_file_and_escaped_output_in_both_themes(self):
        """The newest log opens by default and its content is inert text."""
        older = self.logs / "island-261124.log"
        latest = self.logs / "island-261125.log"
        older.write_text("earlier entry", encoding="utf-8")
        os.utime(older, (100, 100))
        latest.write_text("<script>alert(1)</script> {{ 7 * 7 }}", encoding="utf-8")
        self._login(self.admin)
        templates = ROOT / "webapp/app/templates"
        for theme in ("readable.css", "plum.css"):
            loader = FileSystemLoader(templates)
            base = "appbuilder/baselayout.html"
            if theme == "plum.css":
                loader = ChoiceLoader(
                    [FileSystemLoader(templates / "themes/plum"), loader]
                )
                base = "plum_baselayout.html"
            with self.subTest(theme=theme), patch.dict(
                self.app.config, APP_THEME=theme
            ), patch.object(self.app, "jinja_loader", loader), patch.object(
                self.builder, "base_template", base
            ):
                self.app.jinja_env.cache.clear()
                response = self.client.get(URL)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertIn(b'value="island-261125.log" selected', response.data)
                self.assertIn(b'value="island-261124.log"', response.data)
                self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", response.data)
                self.assertIn(b"{{ 7 * 7 }}", response.data)
                self.assertNotIn(b"<script>alert(1)</script>", response.data)
                self.assertIn(b"js/plum_logs.js", response.data)
        response = self.client.get(URL, query_string={"file": older.name})
        self.assertIn(b"earlier entry", response.data)

    def test_listing_and_open_refuse_non_log_paths(self):
        """A selectable name must be a regular .log file in the directory."""
        self._login(self.admin)
        outside = self.directory / "private.log"
        outside.write_text("outside directory fixture", encoding="utf-8")
        (self.logs / "linked.log").symlink_to(outside)
        (self.logs / "directory.log").mkdir()
        (self.logs / "config.txt").touch()
        (self.logs / "valid.log").touch()
        html = self.client.get(URL).data
        self.assertIn(b'value="valid.log"', html)
        for name in (
            "linked.log",
            "directory.log",
            "config.txt",
            "../private.log",
            str(outside),
        ):
            with self.subTest(name=name):
                response = self.client.get(URL, query_string={"file": name})
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(b"outside directory fixture", response.data)
        with patch.object(logs_view, "_list_logs", return_value=["directory.log"]):
            response = self.client.get(URL, query_string={"file": "directory.log"})
            self.assertEqual(response.status_code, 404)

    def test_large_log_opens_at_end_with_bounded_response(self):
        """An 80 MiB log only returns the recent block on the first request."""
        self._login(self.admin)
        cap = logs_view.LOG_PAGE_BYTES
        with (self.logs / "large.log").open("wb") as stream:
            stream.write(b"old sentinel\n")
            stream.seek(80 * 1024 * 1024)
            stream.write(b"\nlatest sentinel\n")
        response = self.client.get(URL)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"latest sentinel", response.data)
        self.assertNotIn(b"old sentinel", response.data)
        self.assertIn(b"before=", response.data)
        self.assertLess(len(response.data), 2 * cap)

    def test_pages_preserve_line_boundaries_and_validate_offsets(self):
        """Older/newer links follow file positions and reject invalid cursors."""
        self._login(self.admin)
        lines = [f"Entry {index} β\n" for index in range(1, 7)]
        (self.logs / "chunk.log").write_text("".join(lines), encoding="utf-8")
        with patch.object(logs_view, "LOG_PAGE_BYTES", 26):
            latest = self.client.get(URL).get_data(as_text=True)
            older_url = unescape(re.search(r'href="([^"]+)">Older</a>', latest)[1])
            older = self.client.get(older_url).get_data(as_text=True)
            newer_url = unescape(re.search(r'href="([^"]+)">Newer</a>', older)[1])
            newer = self.client.get(newer_url).get_data(as_text=True)
        self.assertIn("".join(lines[-2:]), latest)
        self.assertIn("".join(lines[2:4]), older)
        self.assertIn("".join(lines[-2:]), newer)
        for argument in (
            {"before": "-1"},
            {"after": "a"},
            {"before": "0"},
            {"before": "1", "after": "2"},
        ):
            with self.subTest(argument=argument):
                self.assertEqual(
                    self.client.get(URL, query_string=argument).status_code, 400
                )


if __name__ == "__main__":
    unittest.main()
