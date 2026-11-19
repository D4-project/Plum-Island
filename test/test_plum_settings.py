"""Configuration saves must be durable, private and separate from live workers."""

import ast
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from werkzeug.datastructures import MultiDict

from plum_settings.forms import cards_for, overrides_from_form
from plum_settings.registry import SETTINGS, SettingsError, parse_value
from plum_settings.store import (
    SettingsConflict,
    SettingsStore,
    apply_settings,
    child_settings_environment,
    tool_configuration,
    publish_controller_settings,
    pin_controller_for_worker,
)

ROOT = Path(__file__).resolve().parents[1]


class PlumSettingsTest(unittest.TestCase):
    """Use temporary files only; never import the running application."""

    def setUp(self):
        """Start a small controller configuration in private disposable storage."""
        directory = self.enterContext(
            TemporaryDirectory()  # pylint: disable=consider-using-with
        )  # pylint: disable=consider-using-with
        self.directory = Path(directory) / "settings"
        self.enterContext(patch.dict(os.environ, PLUM_SETTINGS_DIR=str(self.directory)))
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("PLUM_SETTINGS_SNAPSHOT", None)
        self.baseline = {
            "KVROCKS_HOST": "old-backend",
            "MEILI_KEY": "existing-secret",
            "TLDADD": ["local"],
        }
        self.config = dict(self.baseline)
        self.runtime = apply_settings(self.config)
        publish_controller_settings(self.config)
        self.store = self.runtime.store

    def test_inventory_covers_custom_template_settings_and_defaults(self):
        """New template settings must be classified, never silently omitted."""
        excluded = {
            "SECRET_KEY",
            "SQLALCHEMY_DATABASE_URI",
            "CSRF_ENABLED",
            "APP_NAME",
            "FAB_BASE_TEMPLATE",
            "FAB_API_SWAGGER_UI",
            "AUTH_TYPE",
            "BABEL_DEFAULT_LOCALE",
            "BABEL_DEFAULT_FOLDER",
            "LANGUAGES",
            "UPLOAD_FOLDER",
            "IMG_UPLOAD_FOLDER",
            "IMG_UPLOAD_URL",
            "APP_THEME",
        }
        keys = {}
        tree = ast.parse((ROOT / "webapp/config.py.template").read_text())
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        keys[target.id] = statement.value
        self.assertEqual(set(keys) - excluded, set(SETTINGS))
        for key, field in SETTINGS.items():
            if key in {"MEILI_KEY", "JSON_FOLDER", "EXPORT_JOBS_FOLDER"}:
                continue
            with self.subTest(key=key):
                expected = ast.literal_eval(keys[key])
                self.assertEqual(
                    list(field.default) if key == "TLDADD" else field.default, expected
                )

    def test_save_is_pending_until_restart_and_children_keep_parent_revision(self):
        """A child launched after a save must still use its parent's backend."""
        saved = self.store.save("0", {"KVROCKS_HOST": "new-backend"}, self.baseline)
        self.assertEqual(self.runtime.pending(saved), ["KVROCKS_HOST"])
        environment = child_settings_environment(self.config)
        self.assertNotIn("existing-secret", repr(environment))
        with patch.dict(os.environ, environment):
            child = {"KVROCKS_HOST": "edited-config-file", "MEILI_KEY": "different"}
            apply_settings(child)
            self.assertEqual(child["KVROCKS_HOST"], "old-backend")
            self.assertEqual(child["MEILI_KEY"], "existing-secret")
        restarted = dict(self.baseline)
        runtime = apply_settings(restarted)
        self.assertEqual(restarted["KVROCKS_HOST"], "new-backend")
        self.assertFalse(runtime.pending(saved))
        self.assertEqual(self.config["KVROCKS_HOST"], "old-backend")
        self.assertEqual(self.runtime.pending(saved), ["KVROCKS_HOST"])

    def test_tools_follow_applied_configuration_not_pending_edits(self):
        """Offline administration cannot accidentally use a pending backend."""
        self.store.save("0", {"KVROCKS_HOST": "new-backend"}, self.baseline)
        module = SimpleNamespace(**self.baseline)
        self.assertEqual(tool_configuration(module)["KVROCKS_HOST"], "old-backend")
        restarted = dict(self.baseline)
        apply_settings(restarted)
        publish_controller_settings(restarted)
        self.assertEqual(tool_configuration(module)["KVROCKS_HOST"], "new-backend")

    def test_missing_overrides_preserve_legacy_runtime_defaults(self):
        """A missing template setting keeps its existing consumer's fallback."""
        self.assertNotIn("MEILI_HTTP_TIMEOUT_SECONDS", self.config)
        self.assertEqual(self.config["MEILI_KEY"], self.baseline["MEILI_KEY"])
        self.assertEqual(self.store.desired()["overrides"], {})

    def test_explicit_default_for_absent_setting_is_a_real_pending_change(self):
        """A displayed template default must not masquerade as an applied value."""
        desired = self.store.desired()
        cards = cards_for(self.runtime, desired)
        field = next(
            item
            for card in cards
            for item in card["fields"]
            if item["definition"].key == "MEILI_HTTP_TIMEOUT_SECONDS"
        )
        self.assertTrue(field["inherited"])
        self.assertEqual(field["value"], "")
        self.assertEqual(field["default"], "10")
        overrides = overrides_from_form(
            MultiDict({"MEILI_HTTP_TIMEOUT_SECONDS": "10"}), desired, self.baseline
        )
        saved = self.store.save("0", overrides, self.baseline)
        self.assertEqual(self.runtime.pending(saved), ["MEILI_HTTP_TIMEOUT_SECONDS"])
        restarted = dict(self.baseline)
        apply_settings(restarted)
        self.assertEqual(restarted["MEILI_HTTP_TIMEOUT_SECONDS"], 10)

    def test_helper_import_does_not_publish_pending_backend(self):
        """Importing the app in an auxiliary tool is not a controller restart."""
        self.store.save("0", {"KVROCKS_HOST": "pending"}, self.baseline)
        apply_settings(dict(self.baseline))
        self.assertEqual(
            tool_configuration(SimpleNamespace(**self.baseline))["KVROCKS_HOST"],
            "old-backend",
        )

    def test_manual_worker_uses_applied_revision_and_refuses_unapplied_settings(self):
        """Standalone worker startup must not bypass the scheduler's configuration."""
        self.store.save("0", {"KVROCKS_HOST": "pending"}, self.baseline)
        with patch.dict(os.environ):
            pin_controller_for_worker()
            worker = dict(self.baseline)
            apply_settings(worker)
            self.assertEqual(worker["KVROCKS_HOST"], "old-backend")
        (self.directory / "applied.json").unlink()
        with self.assertRaises(SettingsError):
            pin_controller_for_worker()

    def test_concurrent_writers_cannot_lose_updates(self):
        """Two independent store instances submitting the same revision conflict."""

        def save(host):
            try:
                return SettingsStore(self.directory).save(
                    "0", {"KVROCKS_HOST": host}, self.baseline
                )["revision"]
            except SettingsConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, ["first", "second"]))
        self.assertEqual(results.count("conflict"), 1)
        self.assertIn(
            self.store.desired()["overrides"]["KVROCKS_HOST"], {"first", "second"}
        )

    def test_failed_atomic_replace_preserves_previous_configuration(self):
        """Disk failure must not leave truncated JSON or change the revision."""
        saved = self.store.save("0", {"KVROCKS_PORT": 7777}, self.baseline)
        replace = os.replace

        def fail_current(source, destination):
            if Path(destination).name == "settings.json":
                raise OSError("disk full")
            return replace(source, destination)

        with patch("plum_settings.store.os.replace", side_effect=fail_current):
            with self.assertRaises(SettingsError):
                self.store.save(
                    saved["revision"], {"KVROCKS_PORT": 8888}, self.baseline
                )
        self.assertEqual(self.store.desired(), saved)
        self.assertFalse(list(self.directory.glob(".write-*")))

    def test_private_files_backup_and_recovery(self):
        """Credentials and snapshots are private; restoring the backup is usable."""
        saved = self.store.save("0", {"MEILI_KEY": "new-secret"}, self.baseline)
        self.store.save(saved["revision"], {"MEILI_KEY": "next-secret"}, self.baseline)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        for path in self.directory.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        os.replace(
            self.directory / "settings.previous.json", self.directory / "settings.json"
        )
        restarted = dict(self.baseline)
        apply_settings(restarted)
        self.assertEqual(restarted["MEILI_KEY"], "new-secret")

    def test_corrupt_or_redirected_files_fail_closed(self):
        """Invalid JSON, unknown keys, symlinks and unsafe permissions are rejected."""
        path = self.directory / "settings.json"
        for record in (
            "broken",
            {"version": 1, "revision": "0", "overrides": {"AUTH_TYPE": 1}},
        ):
            self.store.write("settings.json", record)
            with self.assertRaises(SettingsError):
                self.store.desired()
        path.unlink()
        path.symlink_to(self.directory / self.runtime.snapshot_name)
        with self.assertRaises(SettingsError):
            self.store.desired()
        path.unlink()
        self.store.write(
            "settings.json", {"version": 1, "revision": "0", "overrides": {}}
        )
        path.chmod(0o644)
        with self.assertRaises(SettingsError):
            self.store.desired()

    def test_validation_rejects_unsafe_types_and_dependent_options(self):
        """Validate settings without echoing a submitted value in errors."""
        for key, value in (
            ("KVROCKS_PORT", 65536),
            ("KVROCKS_PORT", True),
            ("TAG_RECONCILIATION_PAUSE_SECONDS", "nan"),
            ("TAG_RECONCILIATION_PAUSE_SECONDS", "inf"),
            ("MEILI_DATABASE_URI", "https://secret:password@example.org"),
            ("MEILI_DATABASE_URI", "file:///tmp/data"),
            ("LOG_FILE_PREFIX", "../outside"),
            ("LOG_ENABLED", "yes"),
            ("TLDADD", [1]),
            ("REPORT_SMTP_FROM", "user@example.org\r\nBcc:leak@example.org"),
            ("REPORT_SMTP_FROM", "user%route@example.org"),
            ("REPORT_SMTP_FROM", "user@xn--example.test"),
            ("SCHEDULER_QUEUE_STATE_BATCH_SIZE", 257),
        ):
            with self.subTest(key=key), self.assertRaises(SettingsError) as caught:
                parse_value(SETTINGS[key], value)
            self.assertNotIn(str(value), str(caught.exception))
        for overrides in (
            {"REPORT_SMTP_USE_TLS": True, "REPORT_SMTP_USE_SSL": True},
            {"TAG_RECONCILIATION_QUIET_SECONDS": 20},
            {"TAG_RECONCILIATION_MIN_PLANNING_BATCH_SIZE": 2000},
            {"SCAN_DELAY": 24},
            {"AUTH_TYPE": 1},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(SettingsError):
                self.store.save("0", overrides, self.baseline)
        self.assertEqual(self.store.desired()["revision"], "0")

    def test_secrets_are_retained_and_never_presented_to_templates(self):
        """Credential actions are explicit and presentation contains no raw values."""
        desired = self.store.desired()
        self.assertNotIn("existing-secret", repr(cards_for(self.runtime, desired)))
        self.assertEqual(
            overrides_from_form(
                MultiDict({"secret_action_MEILI_KEY": "keep"}), desired, self.baseline
            ),
            {},
        )
        replaced = overrides_from_form(
            MultiDict(
                {
                    "secret_action_MEILI_KEY": "replace",
                    "secret_value_MEILI_KEY": "replacement",
                }
            ),
            desired,
            self.baseline,
        )
        self.assertEqual(replaced, {"MEILI_KEY": "replacement"})
        for data in (
            {"secret_action_MEILI_KEY": "clear"},
            {"AUTH_TYPE": "1"},
            {"SCAN_DELAY": "2"},
            {"secret_value_MEILI_KEY": "not-confirmed"},
        ):
            with self.assertRaises(SettingsError):
                overrides_from_form(MultiDict(data), desired, self.baseline)
        with self.assertRaises(SettingsError):
            overrides_from_form(
                MultiDict([("LOG_ENABLED", "true"), ("LOG_ENABLED", "false")]),
                desired,
                self.baseline,
            )

    def test_restore_config_value_and_noop_saves(self):
        """Resetting an override returns to config.py; unchanged saves do not churn."""
        desired = self.store.save("0", {"KVROCKS_HOST": "override"}, self.baseline)
        self.assertEqual(
            self.store.save(desired["revision"], desired["overrides"], self.baseline),
            desired,
        )
        overrides = overrides_from_form(
            MultiDict({"reset_KVROCKS_HOST": "true"}), desired, self.baseline
        )
        restored = self.store.save(desired["revision"], overrides, self.baseline)
        self.assertFalse(self.runtime.pending(restored))

    def test_pinned_snapshot_is_required_and_cannot_escape_directory(self):
        """A missing or invalid inherited snapshot must never fall back to latest."""
        for name in ("../settings.json", "runtime-" + "a" * 32 + ".json"):
            with patch.dict(os.environ, PLUM_SETTINGS_SNAPSHOT=name):
                with self.assertRaises(SettingsError):
                    apply_settings(dict(self.baseline))

    def test_applied_snapshot_remains_usable_after_later_boots(self):
        """Restarting another web process cannot invalidate an older live parent."""
        environment = child_settings_environment(self.config)
        self.store.save("0", {"KVROCKS_HOST": "next"}, self.baseline)
        apply_settings(dict(self.baseline))
        with patch.dict(os.environ, environment):
            child = dict(self.baseline)
            apply_settings(child)
        self.assertEqual(child["KVROCKS_HOST"], "old-backend")
