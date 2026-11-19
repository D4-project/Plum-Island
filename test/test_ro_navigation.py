"""Read Only menu and route access match the visible search and stats UI."""

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app import app, appbuilder
from app.views import KVSearchView
from tools.initial_setup import load_role_definition, normalize_permission_label

ROLE_FILE = Path(__file__).resolve().parents[1] / "webapp/security_roles/read_only.yaml"


def read_only_permissions():
    """Use the same parser as the deployment role sync command."""
    role_name, labels = load_role_definition(ROLE_FILE)
    if role_name != "Read Only":
        raise AssertionError(f"Unexpected role: {role_name}")
    return {normalize_permission_label(label) for label in labels}


def menu_names(items):
    """Flatten the actual FAB menu structure."""
    names = set()
    for item in items:
        if isinstance(item, dict):
            names.add(item["name"])
            names.update(menu_names(item.get("childs", [])))
    return names


class ReadOnlyNavigationTest(unittest.TestCase):
    """Check role YAML against registered menus and protected routes."""

    def test_menu_shows_search_and_stats_but_hides_bulk_import(self):
        """Menu item names must match the current FAB registration."""
        permissions = read_only_permissions()
        allowed_menus = {
            view for permission, view in permissions if permission == "menu_access"
        }
        with app.test_request_context(), patch.object(
            appbuilder.sm, "get_user_menu_access", return_value=allowed_menus
        ):
            names = menu_names(appbuilder.menu.get_data())
        self.assertTrue({"Analytics", "Search Scans", "Token Search"} <= names)
        self.assertTrue({"Status", "Stats"} <= names)
        self.assertNotIn("Bulk Import", names)

    def test_ro_can_open_search_and_stats_routes(self):
        """Visible entries reach their pages with the RO permission set."""
        permissions = read_only_permissions()
        with patch.object(
            appbuilder.sm,
            "has_access",
            side_effect=lambda permission, view: (permission, view) in permissions,
        ), patch("app.views.KVrocksIndexer") as indexer, patch.object(
            KVSearchView, "_collect_tag_catalogue", return_value=[]
        ):
            indexer.return_value.objects_count.return_value = {
                "uid_count": 0,
                "ip_count": 0,
            }
            client = app.test_client()
            for path in (
                "/kvsearchview/search",
                "/meilisearchview/search",
                "/statsview/",
            ):
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)

    def test_search_requests_and_bulk_import_permission(self):
        """Search calls work; Bulk Import UI and API stay denied."""
        permissions = read_only_permissions()
        for permission, view in (
            ("can_query", "KVSearchView"),
            ("can_tags", "KVSearchView"),
            ("can_expand_ips", "KVSearchView"),
            ("can_tag_suggest", "KVSearchView"),
            ("can_header_suggest", "KVSearchView"),
            ("can_query", "MeiliSearchView"),
            ("can_getuid", "MeiliSearchView"),
        ):
            with self.subTest(permission=permission, view=view):
                self.assertIn((permission, view), permissions)
        self.assertNotIn(("can_bulk_import", "TargetsApi"), permissions)
        self.assertNotIn(("can_bulk_import", "TargetsView"), permissions)

        with patch.object(
            appbuilder.sm,
            "has_access",
            side_effect=lambda permission, view: (permission, view) in permissions,
        ), patch("app.views.client") as meili:
            meili.index.return_value.search.return_value = {"hits": []}
            meili.index.return_value.get_document.return_value = SimpleNamespace(
                uid="scan-1"
            )
            client = app.test_client()
            self.assertEqual(
                client.get("/meilisearchview/query?q=example").status_code, 200
            )
            self.assertEqual(
                client.get("/meilisearchview/getuid?uid=scan-1").status_code, 200
            )
            self.assertIn(
                client.get("/targetsview/bulk_import").status_code, (302, 403)
            )
            self.assertNotEqual(
                client.post(
                    "/targets_api/bulk_import", json={"targets": []}
                ).status_code,
                200,
            )
