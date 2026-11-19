"""Exercise stale-permission cleanup using FAB models and isolated SQLite DBs."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from flask import Flask
from flask_appbuilder import AppBuilder, SQLA
from flask_appbuilder.security.sqla.models import PermissionView, Role
from sqlalchemy.exc import SQLAlchemyError

SPEC = importlib.util.spec_from_file_location(
    "plum_security_cleanup",
    Path(__file__).resolve().parents[1] / "webapp/app/security.py",
)
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)


class PermissionCleanupTest(unittest.TestCase):
    """Run real FAB synchronization without importing Plum or its scheduler."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SECRET_KEY="isolated-permission-cleanup-test",
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            WTF_CSRF_ENABLED=False,
        )
        context = self.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        self.db = SQLA(self.app)
        self.builder = AppBuilder(
            self.app,
            self.db.session,
            security_manager_class=SECURITY.CustomSecurityManager,
        )
        self.sm = self.builder.sm
        self.addCleanup(self.db.engine.dispose)
        self.addCleanup(self.db.session.remove)

    def pair(self, permission, view):
        """Look up an actual persisted permission-view pair."""
        return self.sm.find_permission_view_menu(permission, view)

    def seed_stale(self):
        """Reproduce the five obsolete permissions reported in issue #260."""
        self.sm.add_permissions_view(["can_list", "custom_action"], "TargetsView")
        self.sm.add_permissions_view(
            [
                "can_list",
                "can_show",
                "can_add",
                "can_download",
                "can_delete",
                "can_edit",
            ],
            "TargetScanStatesView",
        )
        operator = self.sm.add_role("Operator")
        for permission in ("can_add", "can_download", "can_delete", "can_edit"):
            self.sm.add_permission_role(
                operator, self.pair(permission, "TargetScanStatesView")
            )
        return operator.id

    def synchronize(self):
        """Use the currently registered permissions of the two affected views."""
        self.sm.add_permissions_view(["can_list"], "TargetsView")
        self.sm.add_permissions_view(["can_list", "can_show"], "TargetScanStatesView")

    def snapshot(self):
        """Record pairs and role grants for preservation/idempotence checks."""
        pairs = {
            (pair.permission.name, pair.view_menu.name)
            for pair in self.db.session.query(PermissionView).all()
        }
        roles = {
            role.name: {
                (pair.permission.name, pair.view_menu.name) for pair in role.permissions
            }
            for role in self.db.session.query(Role).all()
        }
        return pairs, roles

    def test_reported_pairs_removed_from_all_roles_without_refusal_warnings(self):
        """Remove all five stale pairs, including grants shared by two roles."""
        operator_id = self.seed_stale()
        with patch("flask_appbuilder.security.sqla.manager.log.warning") as warning:
            self.synchronize()
        warning.assert_not_called()
        self.assertIsNone(self.pair("custom_action", "TargetsView"))
        for permission in ("can_add", "can_download", "can_delete", "can_edit"):
            self.assertIsNone(self.pair(permission, "TargetScanStatesView"))
        operator = self.db.session.get(Role, operator_id)
        self.assertEqual(operator.permissions, [])
        remaining = self.db.session.execute(
            "SELECT count(*) FROM ab_permission_view_role r "
            "LEFT JOIN ab_permission_view p ON p.id = r.permission_view_id "
            "WHERE p.id IS NULL"
        ).scalar()
        self.assertEqual(remaining, 0)

    def test_active_actions_shared_permissions_and_unrelated_roles_preserved(self):
        """Retain valid action grants and same-named permissions on other views."""
        self.seed_stale()
        self.sm.add_permissions_view(["custom_action", "can_edit"], "OtherView")
        self.sm.add_permissions_view(["can_list", "export_results"], "ActiveView")
        reader = self.sm.add_role("Read Only")
        self.sm.add_permission_role(reader, self.pair("can_list", "ActiveView"))
        before = self.snapshot()
        self.synchronize()
        after = self.snapshot()
        removed = {
            ("custom_action", "TargetsView"),
            *(
                (name, "TargetScanStatesView")
                for name in ("can_add", "can_download", "can_delete", "can_edit")
            ),
        }
        self.assertEqual(after[0], before[0] - removed)
        for role, grants in before[1].items():
            self.assertEqual(after[1][role], grants - removed)
        self.assertIsNotNone(self.sm.find_permission("custom_action"))
        self.assertIsNotNone(self.sm.find_permission("can_edit"))

    def test_repeated_sync_has_no_cleanup_commits_or_warnings(self):
        """The second registration pass preserves all pairs and role grants."""
        self.seed_stale()
        self.synchronize()
        before = self.snapshot()
        with patch.object(
            self.db.session, "commit", wraps=self.db.session.commit
        ) as commit, patch(
            "flask_appbuilder.security.sqla.manager.log.warning"
        ) as warning:
            self.synchronize()
        commit.assert_not_called()
        warning.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_fresh_view_still_gets_normal_admin_permissions(self):
        """New views use FAB's existing registration and grant behavior."""
        self.sm.add_permissions_view(["can_list", "custom_action"], "FreshView")
        admin = self.sm.find_role("Admin")
        for name in ("can_list", "custom_action"):
            self.assertIn(self.pair(name, "FreshView"), admin.permissions)
        self.sm.add_permissions_view([], "EmptyView")
        self.assertIsNotNone(self.sm.find_view_menu("EmptyView"))

    def test_commit_failure_rolls_back_all_pair_and_role_changes(self):
        """Abort synchronization rather than continue with partially cleaned ACLs."""
        self.seed_stale()
        before = self.snapshot()
        with patch.object(
            self.db.session, "commit", side_effect=SQLAlchemyError("DB unavailable")
        ), patch.object(
            self.db.session, "rollback", wraps=self.db.session.rollback
        ) as rollback:
            with self.assertRaisesRegex(RuntimeError, "TargetScanStatesView"):
                self.sm.add_permissions_view(
                    ["can_list", "can_show"], "TargetScanStatesView"
                )
        rollback.assert_called_once()
        self.assertEqual(self.snapshot(), before)

    def test_query_failure_is_reported_and_rolled_back(self):
        """A failed cleanup lookup cannot fall through to FAB synchronization."""
        before = self.snapshot()
        with patch.object(
            self.sm, "find_view_menu", side_effect=SQLAlchemyError("DB unavailable")
        ), patch.object(
            self.db.session, "rollback", wraps=self.db.session.rollback
        ) as rollback:
            with self.assertRaisesRegex(RuntimeError, "TargetsView"):
                self.sm.add_permissions_view(["can_list"], "TargetsView")
        rollback.assert_called_once()
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
