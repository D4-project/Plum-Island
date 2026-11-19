"""Exercise real FAB authorization, CSRF and settings templates on disposable SQL."""

import importlib.util
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from test.test_security_permission_cleanup import SECURITY
from test.test_ui_theme import UI_THEME

from flask import Flask, g
from flask_appbuilder import AppBuilder, SQLA
from flask_wtf.csrf import generate_csrf
from flask_login import login_user
from jinja2 import ChoiceLoader, FileSystemLoader

from plum_settings import apply_settings
from plum_settings.forms import cards_for

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "isolated_settings_view", ROOT / "webapp/app/settings_view.py"
)
SETTINGS_VIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETTINGS_VIEW)


class PlumSettingsUiTest(unittest.TestCase):
    """Use actual users/roles; forged permissions must still fail closed."""

    def setUp(self):
        """Start a standalone settings page, with no scheduler or backend clients."""
        directory = self.enterContext(
            TemporaryDirectory()  # pylint: disable=consider-using-with
        )  # pylint: disable=consider-using-with
        self.enterContext(
            patch.dict(os.environ, PLUM_SETTINGS_DIR=str(Path(directory) / "settings"))
        )
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("PLUM_SETTINGS_SNAPSHOT", None)
        self.app = Flask("settings-ui", root_path=str(ROOT / "webapp/app"))
        self.app.config.update(
            SECRET_KEY="test-settings-csrf-only",
            SQLALCHEMY_DATABASE_URI="sqlite://",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            AUTH_ROLE_ADMIN="Settings Admin",
            APP_THEME="plum.css",
            WTF_CSRF_ENABLED=True,
            TESTING=True,
            MEILI_KEY="hidden-meili-credential",
            PASSIVE_PWD="hidden-passive-credential",
            REPORT_SMTP_PASSWORD="hidden-smtp-credential",
            KVROCKS_HOST="localhost",
        )
        self.runtime = apply_settings(self.app.config)
        self.app.context_processor(SETTINGS_VIEW.settings_template_context)
        UI_THEME.configure_ui_templates(self.app)
        context = self.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        self.db = SQLA(self.app)
        self.builder = AppBuilder(
            self.app,
            self.db.session,
            security_manager_class=SECURITY.CustomSecurityManager,
        )
        self.addCleanup(self.db.engine.dispose)
        self.addCleanup(self.db.session.remove)
        self.builder.add_view(
            SETTINGS_VIEW.PlumSettingsView,
            "Plum Settings",
            category="Security",
            menu_cond=self.builder.sm.is_plum_settings_admin,
        )
        self.app.jinja_env.globals["csrf_token"] = generate_csrf
        self.admin = self.builder.sm.add_user(
            "settings-admin",
            "Settings",
            "Admin",
            "admin@example.org",
            self.builder.sm.find_role("Settings Admin"),
            password="fixture-only",
        )
        operator_role = self.builder.sm.add_role("Settings Operator")
        self.operator = self.builder.sm.add_user(
            "settings-operator",
            "Settings",
            "Operator",
            "operator@example.org",
            operator_role,
            password="fixture-only",
        )
        self.client = self.app.test_client()

    def login(self, user):
        """Install a normal session backed by the fixture's real user loader."""
        g.pop("_login_user", None)
        with self.client.session_transaction() as session:
            session.clear()
            session["_user_id"] = str(user.id)
            session["_fresh"] = True

    def page(self):
        """Require successful rendering of the actual protected route."""
        response = self.client.get("/plumsettings/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        return response.get_data(as_text=True)

    def form(self):
        """Take revision and CSRF tokens from the actual page, as a browser does."""
        page = self.page()
        return {
            name: re.search(r'name="' + name + r'" value="([^"]+)"', page).group(1)
            for name in ("csrf_token", "revision")
        }

    def test_admin_rendering_defaults_restart_help_and_secrets_in_all_themes(self):
        """Verify full pages and script selection in Plum, Readable and Flatly."""
        self.login(self.admin)
        templates = ROOT / "webapp/app/templates"
        for theme in ("plum.css", "readable.css", "flatly.css"):
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
                page = self.page()
                self.assertEqual(page.count('<section class="settings-card"'), 9)
                self.assertEqual(page.count("<strong>Default:</strong>"), 49)
                self.assertEqual(page.count("<strong>Restart required:</strong>"), 48)
                self.assertNotIn("LOG_ROTATION_DAYS", page)
                self.assertNotIn("Legacy rotation interval", page)
                self.assertIn('name="LOG_RETENTION_DAYS"', page)
                self.assertIn("Restart Plum-Agent to apply changes.", page)
                self.assertNotIn("Web application and scheduler", page)
                self.assertNotIn("Use runtime default", page)
                self.assertRegex(page, r'name="KVROCKS_PORT"[^>]*value="6666"')
                self.assertRegex(
                    page, r'name="MEILI_HTTP_TIMEOUT_SECONDS"[^>]*value="10"'
                )
                self.assertIn('<option value="false" selected>False', page)
                self.assertIn("<option selected>WARNING</option>", page)
                self.assertIn("Connectivity to Meilisearch", page)
                self.assertIn("Default:</strong> 6666", page)
                self.assertIn("Default:</strong> 10 seconds", page)
                self.assertIn("Default:</strong> False", page)
                self.assertIn("js/plum_settings.js", page)
                self.assertEqual(
                    "themes/plum/color_mode.js" in page, theme == "plum.css"
                )
                for secret in (
                    "hidden-meili-credential",
                    "hidden-passive-credential",
                    "hidden-smtp-credential",
                ):
                    self.assertNotIn(secret, page)
                for key in ("AUTH_TYPE", "APP_THEME", "FAB_BASE_TEMPLATE"):
                    self.assertNotIn(f'name="{key}"', page)

    def test_non_admin_direct_requests_and_misassigned_permissions_are_denied(self):
        """Both menu and endpoints stay inaccessible even with explicit FAB grants."""
        for permission, view in (
            ("can_index", "PlumSettingsView"),
            ("menu_access", "Plum Settings"),
            ("menu_access", "Security"),
        ):
            pair = self.builder.sm.find_permission_view_menu(permission, view)
            self.builder.sm.add_permission_role(self.operator.roles[0], pair)
        for user in (None, self.operator):
            with self.subTest(user=user):
                if user:
                    self.login(user)
                for method in (self.client.get, self.client.post):
                    response = method("/plumsettings/")
                    self.assertIn(response.status_code, (302, 403))
                    self.assertNotIn(b"hidden-meili-credential", response.data)
        with self.app.test_request_context():
            login_user(self.operator)
            g.user = self.operator
            self.assertNotIn("Plum Settings", self.builder.sm.get_user_menu_access())
            self.assertFalse(self.builder.menu.find("Plum Settings").should_render())
        self.assertEqual(self.runtime.store.desired()["revision"], "0")

    def test_save_validation_csrf_conflict_and_secret_retention(self):
        """A valid save is pending; invalid or stale forms cannot change it."""
        self.login(self.admin)
        form = self.form()
        response = self.client.post(
            "/plumsettings/",
            data={**form, "csrf_token": "invalid", "KVROCKS_PORT": "7777"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.runtime.store.desired()["revision"], "0")
        response = self.client.post(
            "/plumsettings/",
            data={**form, "KVROCKS_PORT": "7777"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Pending restart.", response.data)
        self.assertIn(
            b"Currently applied: <span>Not explicitly configured", response.data
        )
        self.assertIn(b"Default:</strong> 6666", response.data)
        saved = self.runtime.store.desired()
        self.assertEqual(saved["overrides"], {"KVROCKS_PORT": 7777})
        self.assertNotIn("KVROCKS_PORT", self.app.config)
        response = self.client.post(
            "/plumsettings/", data={**form, "KVROCKS_PORT": "8888"}
        )
        self.assertEqual(response.status_code, 409)
        response = self.client.post(
            "/plumsettings/", data={**self.form(), "APP_THEME": "flatly.css"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.runtime.store.desired(), saved)
        self.assertEqual(self.app.config["MEILI_KEY"], "hidden-meili-credential")

    def test_credential_replacement_clear_and_error_redaction(self):
        """The browser never receives saved credentials, even following errors."""
        self.login(self.admin)
        response = self.client.post(
            "/plumsettings/",
            data={
                **self.form(),
                "secret_action_MEILI_KEY": "replace",
                "secret_value_MEILI_KEY": "replacement-secret",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"replacement-secret", response.data)
        self.assertEqual(
            self.runtime.store.desired()["overrides"]["MEILI_KEY"], "replacement-secret"
        )
        response = self.client.post(
            "/plumsettings/",
            data={**self.form(), "secret_action_PASSIVE_PWD": "clear"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.runtime.store.desired()["overrides"]["PASSIVE_PWD"], "")
        response = self.client.post(
            "/plumsettings/",
            data={
                **self.form(),
                "secret_action_MEILI_KEY": "replace",
                "secret_value_MEILI_KEY": "should-not-leak",
                "KVROCKS_PORT": "invalid",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"should-not-leak", response.data)

    def test_saved_values_are_escaped(self):
        """A text setting cannot inject HTML into values, help or pending status."""
        self.login(self.admin)
        attack = '"><script>alert(1)</script>'
        response = self.client.post(
            "/plumsettings/",
            data={**self.form(), "PASSIVE_USER": attack},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(attack.encode(), response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_submit_complete_default_form_does_not_create_overrides(self):
        """A normal browser sends every field; unchanged values stay inherited."""
        self.login(self.admin)
        form = self.form()
        for card in cards_for(self.runtime, self.runtime.store.desired()):
            for item in card["fields"]:
                field = item["definition"]
                if field.inactive:
                    continue
                if field.secret:
                    form[f"secret_action_{field.key}"] = "keep"
                else:
                    if item["inherited"]:
                        form[f"prefilled_{field.key}"] = "true"
                    form[field.key] = (
                        item["value"].lower()
                        if field.value_type == "bool"
                        else item["value"]
                    )
        response = self.client.post("/plumsettings/", data=form)
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        self.assertEqual(self.runtime.store.desired()["overrides"], {})

    def test_restart_banner_persists_on_other_pages_and_clears_after_restart(self):
        """Shared layouts show durable status to every role without exposing values."""
        self.login(self.admin)
        marker = b'id="plum-settings-restart-banner"'
        self.assertNotIn(marker, self.client.get("/").data)
        response = self.client.post(
            "/plumsettings/", data={**self.form(), "KVROCKS_PORT": "7777"}
        )
        self.assertEqual(response.status_code, 302)
        templates = ROOT / "webapp/app/templates"
        for theme in ("plum.css", "readable.css", "flatly.css"):
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
                self.login(self.admin)
                for path in ("/plumsettings/", "/", "/users/list/"):
                    page = self.client.get(path)
                    self.assertEqual(page.status_code, 200, path)
                    self.assertEqual(page.data.count(marker), 1)
                self.login(self.operator)
                page = self.client.get("/")
                self.assertEqual(page.status_code, 200)
                self.assertIn(marker, page.data)
                self.assertNotIn(b"hidden-meili-credential", page.data)
        restarted = dict(self.runtime.baseline)
        apply_settings(restarted)
        self.app.config.update(restarted)
        self.assertNotIn(marker, self.client.get("/").data)

    def test_restart_banner_clears_when_pending_edits_are_reverted(self):
        """Restoring the already-applied values removes the reminder without restart."""
        self.login(self.admin)
        saved = self.runtime.store.save(
            "0", {"KVROCKS_PORT": 7777}, self.runtime.baseline
        )
        self.assertIn('id="plum-settings-restart-banner"', self.page())
        self.runtime.store.save(saved["revision"], {}, self.runtime.baseline)
        self.assertNotIn('id="plum-settings-restart-banner"', self.page())

    def test_unreadable_settings_do_not_break_other_pages(self):
        """Global rendering remains usable when the saved configuration needs recovery."""
        self.login(self.operator)
        self.runtime.store.write("settings.json", "invalid")
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Configuration status unavailable", response.data)
