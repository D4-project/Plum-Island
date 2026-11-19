"""Authenticated discovery contract without live databases or scan backends."""

from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from flask import g
from app import app, appbuilder
from app import discovery_api as api
from app.views import KVSearchView, IPDetailView


class DiscoveryApiTest(unittest.TestCase):
    """Keep actual FAB route protection; replace identity/permissions and storage."""

    def setUp(self):
        self.client = app.test_client()
        self.owner = SimpleNamespace(id=71)
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.guards.enter_context(
            patch.object(appbuilder.sm, "is_item_public", return_value=False)
        )

    def authorize(self, allowed=True):
        """Provide the JWT identity exactly where FAB stores it."""

        def verify():
            g.user = self.owner

        self.guards.enter_context(
            patch(
                "flask_appbuilder.security.decorators.verify_jwt_in_request",
                side_effect=verify,
            )
        )
        self.guards.enter_context(
            patch.object(appbuilder.sm, "has_access", return_value=allowed)
        )

    def post(self, name, data):
        """Call a registered endpoint."""
        return self.client.post("/api/v1/discovery/" + name, json=data)

    def test_all_routes_require_auth_and_permission(self):
        """No adapter grants access merely because the MCP client is connected."""
        for name in ("search", "token_search", "show_ip", "tags", "headers"):
            self.assertIn(self.post(name, {}).status_code, (401, 403))
        self.assertIn(
            self.client.get("/api/v1/discovery/search_help").status_code, (401, 403)
        )
        self.authorize(False)
        with patch.object(api, "KVrocksIndexer") as backend:
            for name in ("search", "token_search", "show_ip", "tags", "headers"):
                self.assertEqual(self.post(name, {}).status_code, 403)
            self.assertEqual(
                self.client.get("/api/v1/discovery/search_help").status_code, 403
            )
        backend.assert_not_called()

    def test_real_login_jwt_and_separate_method_permissions(self):
        """Exercise actual FAB login/JWT without replacing auth or access checks."""
        with app.app_context():
            role = appbuilder.sm.add_role("VirionContractTest")
            grant = appbuilder.sm.add_permission_view_menu(
                "can_search_help", "DiscoveryApi"
            )
            role.permissions = [grant]
            user = appbuilder.sm.add_user(
                "virion-contract-test",
                "Virion",
                "Test",
                "virion@example.invalid",
                role,
                password="test-only-password",
            )
            self.assertIsNotNone(user)
            response = self.client.post(
                "/api/v1/security/login",
                json={
                    "username": "virion-contract-test",
                    "password": "test-only-password",
                    "provider": "db",
                },
            )
            self.assertEqual(response.status_code, 200)
            headers = {"Authorization": "Bearer " + response.json["access_token"]}
            result = self.client.get("/api/v1/discovery/search_help", headers=headers)
            self.assertEqual(result.status_code, 200, result.json)
            denied = self.client.post(
                "/api/v1/discovery/search", json={"query": "port:443"}, headers=headers
            )
            self.assertEqual(denied.status_code, 403)

    @staticmethod
    def page(ips=None, more=True):
        """Minimal real executor-shaped response."""
        return {
            "status": True,
            "results": ips or {},
            "time_range": {"from_ts": 100, "to_ts": 300},
            "pagination": {"has_more": more, "next_cursor": 199},
            "search_id": None,
        }

    def test_search_forwards_grammar_dates_and_binds_retryable_cursor(self):
        """Empty windows continue; signed cursors bind user, dates and seen IPs."""
        self.authorize()
        query = "(port:80 OR port:443) AND tag:lang:php"
        with patch.object(
            KVSearchView,
            "execute_search_page",
            side_effect=[
                self.page(),
                self.page({"8.8.8.8": ["uid"]}),
                self.page(more=False),
            ],
        ) as execute:
            first = self.post("search", {"query": query, "from_ts": 100, "to_ts": 300})
            self.assertEqual(first.status_code, 200)
            cursor = first.json["result"]["next_cursor"]
            self.assertTrue(cursor)
            self.assertEqual(execute.call_args.args, (query, 100, 300))
            second = self.post("search", {"cursor": cursor})
            self.assertEqual(execute.call_args.kwargs["window_days"], 2)
            next_cursor = second.json["result"]["next_cursor"]
            final = self.post("search", {"cursor": next_cursor})
            self.assertEqual(execute.call_args.kwargs["seen_ips"], ["8.8.8.8"])
            self.assertIsNone(final.json["result"]["next_cursor"])
        self.owner.id = 72
        self.assertEqual(self.post("search", {"cursor": cursor}).status_code, 403)
        self.owner.id = 71
        self.assertEqual(
            self.post("search", {"cursor": cursor, "query": "port:22"}).status_code, 400
        )
        self.assertEqual(self.post("search", {"cursor": "broken"}).status_code, 410)
        with patch.object(api, "CURSOR_TTL", -1):
            self.assertEqual(self.post("search", {"cursor": cursor}).status_code, 410)

    def test_since_and_invalid_inputs_before_backend_work(self):
        """Reuse controller time parsing; reject booleans, unknown fields and nested syntax."""
        self.authorize()
        with patch.object(
            KVSearchView, "execute_search_page", return_value=self.page(more=False)
        ) as execute:
            self.assertEqual(
                self.post("search", {"query": "port:443 since:7"}).status_code, 200
            )
            self.assertAlmostEqual(
                execute.call_args.args[2] - execute.call_args.args[1],
                7 * 86400,
                delta=86400,
            )
            execute.reset_mock()
            for data in (
                [],
                {"query": "((port:80))"},
                {"query": "invalid:value"},
                {"query": "port:80", "limit": True},
                {"query": "port:80", "limit": 101},
                {"query": "port:80", "from_ts": 300, "to_ts": 100},
                {"query": "port:80", "from_ts": "yesterday"},
                {"query": "port:80", "typo": 1},
            ):
                self.assertEqual(self.post("search", data).status_code, 400, data)
            execute.assert_not_called()

    def test_token_search_uses_meili_without_structured_rewriting(self):
        """No date/substring promise for free text and preserve upstream ranking."""
        self.authorize()
        with patch.object(api.client, "index") as index:
            index.return_value.search.return_value = {
                "hits": [{"id": "a"}, {"id": "b"}]
            }
            result = self.post(
                "token_search", {"query": "Hello world", "limit": 2, "offset": 4}
            )
            self.assertEqual(result.status_code, 200)
            index.return_value.search.assert_called_once_with(
                "Hello world", {"limit": 2, "offset": 4}
            )
            self.assertEqual(result.json["result"]["next_offset"], 6)
            self.assertEqual(
                self.post("token_search", {"query": "hello", "from_ts": 1}).status_code,
                400,
            )

    def test_ip_scope_matches_web_group_and_reads_only_selected_page(self):
        """IPv6, overlap bounds and missing documents retain precise provenance."""
        self.authorize()
        backend = Mock()
        backend.get_timestamp_for_ip.return_value = {
            "direct": {"first_seen": 100, "last_seen": 250},
            "host": {"first_seen": 50, "last_seen": 400},
            "old": {"first_seen": 10, "last_seen": 20},
        }
        backend.get_requested_hostnames_for_uids.return_value = {
            "host": ["example.org"],
            "old": ["example.org"],
        }
        backend.r.smembers.return_value = {"proto:http"}
        with patch.object(api, "KVrocksIndexer", return_value=backend), patch.object(
            api.client, "index"
        ), patch.object(
            KVSearchView,
            "load_meili_document",
            return_value=(None, "document_not_found", "ignored"),
        ) as load:
            result = self.post(
                "show_ip",
                {
                    "ip": "2001:db8::1",
                    "hostname": "example.org",
                    "from_ts": 100,
                    "to_ts": 300,
                },
            )
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json["result"]["total"], 1)
            self.assertEqual(result.json["result"]["observations"][0]["uid"], "host")
            self.assertEqual(load.call_args.args[1], "host")
            load.reset_mock()
            direct = self.post("show_ip", {"ip": "8.8.8.8"})
            self.assertEqual(direct.json["result"]["observations"][0]["uid"], "direct")
            self.assertEqual(load.call_args.args[1], "direct")
            self.assertEqual(
                self.post(
                    "show_ip", {"ip": "8.8.8.8", "hostname": "absent.example"}
                ).status_code,
                404,
            )
        for ip in ("8.8.8.8/24", "bad", "fe80::1%eth0"):
            self.assertEqual(self.post("show_ip", {"ip": ip}).status_code, 400)
        self.assertEqual(
            IPDetailView.observation_scope(backend, "8.8.8.8")[2], ["direct"]
        )
        backend.get_timestamp_for_ip.return_value = {"min_seen": None, "max_seen": None}
        backend.get_requested_hostnames_for_uids.return_value = {}
        with patch.object(api, "KVrocksIndexer", return_value=backend):
            self.assertEqual(self.post("show_ip", {"ip": "1.1.1.1"}).status_code, 404)

    def test_catalogues_include_all_namespaces_and_header_capabilities(self):
        """Configured tags need not be observed; headers distinguish value collection."""
        self.authorize()
        with patch.object(
            KVSearchView,
            "_collect_rule_tags",
            return_value=["lang:php", "type:router", "vendor:example"],
        ):
            result = self.post("tags", {"prefix": "lang:", "limit": 1}).json["result"]
            self.assertEqual(
                result["tags"], [{"tag": "lang:php", "query": "tag:lang:php"}]
            )
            self.assertIsNone(result["next_offset"])
        with patch.object(api.db.session, "query") as query:
            rows = (
                query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value
            )
            rows.all.return_value = [
                SimpleNamespace(header_name="server", collect_value=False),
                SimpleNamespace(header_name="x-powered-by", collect_value=True),
            ]
            result = self.post("headers", {}).json["result"]["headers"]
            self.assertIsNone(result[0]["value_query_prefix"])
            self.assertEqual(
                result[1]["value_query_prefix"], "http_headval:x-powered-by:"
            )
        help_result = self.client.get("/api/v1/discovery/search_help").json["result"]
        self.assertEqual(
            set(help_result["keywords"]),
            set(KVSearchView.search_keywords()) | {"since", "http_headval"},
        )

    def test_budgets_fail_explicitly_and_backend_errors_are_redacted(self):
        """Never convert backend failure/truncation into a successful empty result."""
        self.authorize()
        with patch.object(
            KVSearchView,
            "execute_search_page",
            side_effect=RuntimeError("secret password"),
        ):
            response = self.post("search", {"query": "port:80"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret", response.get_data(as_text=True))
        with patch.object(api, "MAX_REQUEST_BYTES", 10):
            self.assertEqual(self.post("search", {"query": "port:80"}).status_code, 413)
        with patch.object(api, "MAX_RESPONSE_BYTES", 10):
            self.assertEqual(
                self.client.get("/api/v1/discovery/search_help").status_code, 413
            )
        with patch.object(api, "SLOTS") as slots:
            slots.acquire.return_value = False
            self.assertEqual(
                self.client.get("/api/v1/discovery/search_help").status_code, 503
            )


if __name__ == "__main__":
    unittest.main()
