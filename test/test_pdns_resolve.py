"""Live DNS checks are authorized, bounded, and separate from passive history."""

import copy
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dns.exception
import dns.resolver
from itsdangerous import URLSafeTimedSerializer

from app import app, appbuilder
from app.utils import pdns_resolve as live
from app.views import IPDetailView
from tools.initial_setup import load_role_definition, normalize_permission_label

IP = "185.194.93.47"
HOST = "www.example.org"
ROOT = Path(__file__).resolve().parents[1]


class PdnsResolveTest(unittest.TestCase):
    """Use synthetic records and fake DNS only; never change scan databases."""

    def test_names_and_record_orientation(self):
        """Forward/inverse A records must belong to the viewed address."""
        for record in (
            {"rrtype": "A", "rrname": HOST, "rdata": IP},
            {"rrtype": "a", "rrname": IP, "rdata": HOST},
        ):
            self.assertEqual(live.record_hostname(record, IP), HOST)
            self.assertIsNone(live.record_hostname(record, "185.194.93.48"))
            self.assertIsNone(live.record_hostname(record, "2001:db8::1"))
        for kind in ("AAAA", "TXT", "PTR", None):
            self.assertIsNone(
                live.record_hostname({"rrtype": kind, "rrname": HOST, "rdata": IP}, IP)
            )
        for invalid in (
            IP,
            "::1",
            "localhost",
            "-option.org",
            "a..org",
            "a.org..",
            "https://example.org",
            "a.org;id",
            "a.org\n",
            "x" * 255,
            None,
        ):
            self.assertIsNone(live.normalize_hostname(invalid), invalid)
        self.assertEqual(live.normalize_hostname("WWW.Example.org."), HOST)
        self.assertEqual(live.normalize_hostname("éxample.org"), "xn--xample-9ua.org")

    def test_tokens_preserve_history_and_reject_tampering(self):
        """Only signed, current, same-IP names can reach the resolver."""
        records = [
            {
                "rrtype": "A",
                "rrname": HOST,
                "rdata": IP,
                "time_first": 10,
                "time_last": 20,
            }
        ]
        before = copy.deepcopy(records)
        with patch("app.utils.pdns_resolve.time.time", return_value=100):
            token = live.add_resolve_tokens(records, IP, "test-secret")[0][
                "resolve_token"
            ]
            self.assertEqual(live.verify_resolve_token(token, IP, "test-secret"), HOST)
        self.assertEqual(records, before)
        for value, target in (
            (token + "x", IP),
            (token, "185.194.93.48"),
            (None, IP),
            ("x" * 2049, IP),
        ):
            with self.assertRaises(ValueError):
                live.verify_resolve_token(value, target, "test-secret")
        with patch(
            "app.utils.pdns_resolve.time.time",
            return_value=100 + live.TOKEN_MAX_AGE + 1,
        ):
            with self.assertRaises(ValueError):
                live.verify_resolve_token(token, IP, "test-secret")
        forged = live.add_resolve_tokens(
            [{"rrtype": "TXT", "resolve_hostname": HOST, "resolve_token": token}],
            IP,
            "test-secret",
        )[0]
        self.assertNotIn("resolve_token", forged)

    def test_all_a_answers_and_absolute_lookup(self):
        """Match any A answer, use no search suffix, and retain verification time."""
        with patch.object(live.dns.resolver, "Resolver") as resolver, patch.object(
            live.time, "time", return_value=1234
        ):
            resolver.return_value.resolve.return_value = [
                SimpleNamespace(address="185.194.93.48"),
                SimpleNamespace(address=IP),
            ]
            result = live.resolve_a(HOST, IP)
            self.assertEqual(
                result, {"hostname": HOST, "status": "matched", "checked_at": 1234}
            )
            resolver.return_value.resolve.assert_called_once_with(
                HOST + ".", "A", lifetime=live.LOOKUP_SECONDS, search=False
            )
            resolver.return_value.resolve.return_value = [
                SimpleNamespace(address="185.194.93.48")
            ]
            self.assertEqual(live.resolve_a(HOST, IP)["status"], "mismatch")

    def test_failures_and_slot_release(self):
        """NXDOMAIN/no-answer are not timeouts or server failures."""
        failures = (
            (dns.resolver.NXDOMAIN(), "nxdomain"),
            (dns.resolver.NoAnswer(), "no_answer"),
            (dns.exception.Timeout(), "timeout"),
            (dns.resolver.NoNameservers(), "error"),
            (OSError(), "error"),
        )
        with patch.object(live.dns.resolver, "Resolver") as resolver, patch.object(
            live, "LOOKUP_SLOTS"
        ) as slots:
            slots.acquire.return_value = True
            for error, status in failures:
                resolver.return_value.resolve.side_effect = error
                self.assertEqual(live.resolve_a(HOST, IP)["status"], status)
            self.assertEqual(slots.release.call_count, len(failures))
            slots.acquire.return_value = False
            resolver.reset_mock()
            self.assertEqual(live.resolve_a(HOST, IP)["status"], "busy")
            resolver.assert_not_called()


class PdnsResolveRouteTest(unittest.TestCase):
    """Exercise the registered Flask-AppBuilder route and real CSRF validation."""

    def setUp(self):
        self.client = app.test_client()
        self.url = f"/ip/pdns/resolve/{IP}"
        self.token = live.add_resolve_tokens(
            [{"rrtype": "A", "rrname": HOST, "rdata": IP}], IP, app.secret_key
        )[0]["resolve_token"]
        with self.client.session_transaction() as session:
            session["csrf_token"] = "pdns-test-csrf"
        secret = app.config.get("WTF_CSRF_SECRET_KEY") or app.secret_key
        self.csrf = URLSafeTimedSerializer(secret, salt="wtf-csrf-token").dumps(
            "pdns-test-csrf"
        )

    def test_read_only_permission_and_success(self):
        """Deployment role YAML grants only the actual protected method."""
        _, labels = load_role_definition(ROOT / "webapp/security_roles/read_only.yaml")
        permissions = {normalize_permission_label(label) for label in labels}
        self.assertEqual(
            getattr(IPDetailView.resolve_passive_dns, "_permission_name"),
            "resolve_passive_dns",
        )
        with patch.object(
            appbuilder.sm, "has_access", side_effect=lambda p, v: (p, v) in permissions
        ), patch(
            "app.views.resolve_a",
            return_value={"hostname": HOST, "status": "matched", "checked_at": 10},
        ) as lookup:
            response = self.client.post(
                self.url, json={"token": self.token}, headers={"X-CSRFToken": self.csrf}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "matched")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        lookup.assert_called_once_with(HOST, IP)

    def test_denied_without_permission(self):
        """No DNS activity occurs when FAB rejects a user."""
        with patch.object(appbuilder.sm, "has_access", return_value=False), patch(
            "app.views.resolve_a"
        ) as lookup:
            response = self.client.post(self.url, json={"token": self.token})
        self.assertIn(response.status_code, (302, 403))
        lookup.assert_not_called()

    def test_invalid_requests_never_resolve(self):
        """CSRF, malformed tokens, cross-IP tokens and body size fail closed."""
        with patch.object(appbuilder.sm, "has_access", return_value=True), patch(
            "app.views.resolve_a"
        ) as lookup:
            for url, payload, csrf in (
                (self.url, {"token": self.token}, ""),
                (self.url, {"token": "tampered"}, self.csrf),
                (self.url, {"token": "x" * 5000}, self.csrf),
                (self.url, [], self.csrf),
                (self.url, {"hostname": HOST}, self.csrf),
                ("/ip/pdns/resolve/185.194.93.48", {"token": self.token}, self.csrf),
                ("/ip/pdns/resolve/2001:db8::1", {"token": self.token}, self.csrf),
                ("/ip/pdns/resolve/invalid", {"token": self.token}, self.csrf),
            ):
                response = self.client.post(
                    url, json=payload, headers={"X-CSRFToken": csrf}
                )
                self.assertIn(response.status_code, (400, 413))
            lookup.assert_not_called()

    def test_busy_response_is_explicit(self):
        """Saturation is a retryable per-row result, not a DNS non-match."""
        with patch.object(appbuilder.sm, "has_access", return_value=True), patch(
            "app.views.resolve_a",
            return_value={"hostname": HOST, "status": "busy", "checked_at": None},
        ):
            response = self.client.post(
                self.url, json={"token": self.token}, headers={"X-CSRFToken": self.csrf}
            )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json["status"], "busy")

    def test_pdns_response_signs_eligible_records_without_dns(self):
        """Loading history is not an active lookup; upstream metadata is retained."""
        with patch.object(appbuilder.sm, "has_access", return_value=True), patch.dict(
            app.config, PASSIVE_USER="test", PASSIVE_PWD="test"
        ), patch("app.views.requests.get") as get, patch(
            "app.views.resolve_a"
        ) as lookup:
            get.return_value.text = (
                '{"rrtype":"A","rrname":"www.example.org","rdata":"185.194.93.47",'
                '"time_first":10,"time_last":20}\n'
            )
            response = self.client.get(f"/ip/pdns/{IP}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json[0]["time_last"], 20)
        self.assertEqual(
            live.verify_resolve_token(
                response.json[0]["resolve_token"], IP, app.secret_key
            ),
            HOST,
        )
        lookup.assert_not_called()

    @unittest.skipUnless(shutil.which("node"), "Node.js required for UI test")
    def test_browser_queue_and_stale_responses(self):
        """Run bounded-request, failure and cancellation checks with mocked fetch."""
        subprocess.run(
            [shutil.which("node"), str(ROOT / "test/ip_pdns_resolve_ui.js")],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
