"""Check Read Only WHOIS permission and IP-detail tab responses."""

from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from app import app, appbuilder
from app.views import IPDetailView
from tools.initial_setup import load_role_definition, normalize_permission_label

ROOT = Path(__file__).resolve().parents[1]
ROLE_FILE = ROOT / "webapp/security_roles/read_only.yaml"


class IpWhoisReadOnlyTest(unittest.TestCase):
    """Exercise registered FAB route with the configured RO permission set."""

    @staticmethod
    def _role_permissions():
        role_name, labels = load_role_definition(ROLE_FILE)
        assert role_name == "Read Only"
        return {normalize_permission_label(label) for label in labels}

    def test_ro_can_fetch_whois_without_broader_permission(self):
        """RO YAML grants exactly the route's permission, not a stale name."""
        permissions = self._role_permissions()
        self.assertEqual(
            getattr(IPDetailView.whois_lookup, "_permission_name"), "whois_lookup"
        )
        self.assertIn(("can_whois_lookup", "IPDetailView"), permissions)
        self.assertNotIn(("can_whois", "IPDetailView"), permissions)

        with patch.object(
            appbuilder.sm,
            "has_access",
            side_effect=lambda permission, view: (permission, view) in permissions,
        ) as access, patch(
            "app.views.lookup_network_whois", return_value="WHOIS record"
        ) as lookup:
            response = app.test_client().get("/ip/whois?ip=185.194.93.47")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["result"], "WHOIS record")
        access.assert_any_call("can_whois_lookup", "IPDetailView")
        lookup.assert_called_once_with("185.194.93.47/32")

    def test_user_without_whois_permission_is_denied(self):
        """Do not bypass FAB to make the asynchronous route work."""
        with patch.object(appbuilder.sm, "has_access", return_value=False), patch(
            "app.views.lookup_network_whois"
        ) as lookup:
            response = app.test_client().get("/ip/whois?ip=185.194.93.47")
        self.assertIn(response.status_code, (302, 403))
        lookup.assert_not_called()

    def test_invalid_ip_still_returns_json_error(self):
        """Permission fix leaves server-side IP validation intact."""
        with patch.object(appbuilder.sm, "has_access", return_value=True), patch(
            "app.views.lookup_network_whois"
        ) as lookup:
            response = app.test_client().get("/ip/whois?ip=invalid")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "Enter a valid IP address or CIDR")
        lookup.assert_not_called()

    @unittest.skipUnless(shutil.which("node"), "Node.js required for WHOIS UI check")
    def test_browser_handles_html_and_json_responses(self):
        """The tab reports denied/non-JSON responses without parser errors."""
        subprocess.run(
            [shutil.which("node"), str(ROOT / "test/ip_whois_ui.js")],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
