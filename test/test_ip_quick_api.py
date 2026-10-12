"""IP summary API: bounded dates, indexed values, protection and Swagger."""

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from test.test_kvrocks_search import make_indexer

from werkzeug.datastructures import MultiDict

from app import app, appbuilder
from app.apis import IpQuickApi

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


class IpQuickApiTest(unittest.TestCase):
    """Exercise the registered API without live Kvrocks or JWT service."""

    # Unit tests intentionally exercise the window parser independently.
    # pylint: disable=protected-access

    @staticmethod
    def _authorized():
        """Keep the real FAB decorator, replacing only auth inputs."""
        return (
            patch.object(appbuilder.sm, "is_item_public", return_value=False),
            patch.object(appbuilder.sm, "has_access", return_value=True),
            patch(
                "flask_appbuilder.security.decorators.verify_jwt_in_request",
                return_value=None,
            ),
        )

    def test_default_days_and_explicit_window(self):
        """Defaults to 30 days; date-only stop covers that UTC day."""
        start, stop = IpQuickApi._resolve_window(MultiDict(), now=NOW)
        self.assertEqual((start, stop), (NOW - timedelta(days=30), NOW))

        start, stop = IpQuickApi._resolve_window(MultiDict([("days", "90")]), now=NOW)
        self.assertEqual((start, stop), (NOW - timedelta(days=90), NOW))

        start, stop = IpQuickApi._resolve_window(
            MultiDict([("start", "2026-09-01"), ("stop", "2026-09-30")]),
            now=NOW,
        )
        self.assertEqual(start.isoformat(), "2026-09-01T00:00:00+00:00")
        self.assertEqual(stop.isoformat(), "2026-09-30T23:59:59.999999+00:00")

    def test_invalid_windows_are_rejected(self):
        """Reject ambiguity, future dates, naive datetimes and excess lookback."""
        cases = (
            [("days", "0")],
            [("days", "732")],
            [("days", "30"), ("start", "2026-09-01"), ("stop", "2026-09-30")],
            [("start", "2026-09-01")],
            [("start", "2024-10-11"), ("stop", "2026-10-12")],
            [("start", "2026-10-01"), ("stop", "2026-09-01")],
            [("start", "2026-09-01T12:00:00"), ("stop", "2026-10-01")],
            [("start", "2026-09-01"), ("stop", "2026-10-13")],
            [("days", "30"), ("days", "60")],
        )
        for params in cases:
            with self.subTest(params=params), self.assertRaises(ValueError):
                IpQuickApi._resolve_window(MultiDict(params), now=NOW)

    def test_aggregates_only_reports_last_seen_in_window(self):
        """Exclude old, future and interval-spanning reports without a recent scan."""
        start_ts = int((NOW - timedelta(days=30)).timestamp())
        stop_ts = int(NOW.timestamp())
        indexer = make_indexer(
            {
                "ip:8.8.8.8": {"old", "a", "b", "future", "gap"},
                "ports:old": {"25"},
                "tags:old": {"proto:smtp"},
                "ports:a": {"80", "443"},
                "tags:a": {"proto:http"},
                "ports:b": {"443", "22", "bad", "65536"},
                "tags:b": {"vendor:example", "tag:proto:http"},
                "ports:future": {"53"},
                "tags:future": {"proto:dns"},
                "ports:gap": {"8080"},
                "tags:gap": {"proto:http"},
            }
        )
        for uid, first, last in (
            ("old", start_ts - 1000, start_ts - 1),
            ("a", start_ts - 1000, start_ts + 1),
            ("b", stop_ts, stop_ts),
            ("future", stop_ts + 1, stop_ts + 10),
            ("gap", start_ts - 1000, stop_ts + 1),
        ):
            indexer.r.hashes[f"doc:{uid}"] = {
                "first_seen": first,
                "last_seen": last,
            }

        patches = self._authorized()
        with patches[0], patches[1], patches[2], patch(
            "app.apis.KVrocksIndexer", return_value=indexer
        ), patch.object(
            IpQuickApi,
            "_resolve_window",
            return_value=(NOW - timedelta(days=30), NOW),
        ):
            response = app.test_client().get("/api/v1/ip-quick/8.8.8.8")

        self.assertEqual(response.status_code, 200)
        result = response.json["result"]
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(
            result["ports"],
            [
                {
                    "port": 22,
                    "tags": ["proto:http", "vendor:example"],
                    "last_seen": "2026-10-12T12:00:00Z",
                },
                {
                    "port": 80,
                    "tags": ["proto:http"],
                    "last_seen": "2026-09-12T12:00:01Z",
                },
                {
                    "port": 443,
                    "tags": ["proto:http", "vendor:example"],
                    "last_seen": "2026-10-12T12:00:00Z",
                },
            ],
        )
        self.assertEqual(result["report_count"], 2)
        self.assertNotIn("ports:old", str(indexer.r.batches))
        self.assertNotIn("ports:future", str(indexer.r.batches))
        self.assertNotIn("ports:gap", str(indexer.r.batches))

    def test_unknown_ip_and_empty_window(self):
        """Distinguish unknown address from known IP without recent reports."""
        indexer = make_indexer({"ip:8.8.8.8": {"old"}})
        indexer.r.hashes["doc:old"] = {"first_seen": 1, "last_seen": 2}
        patches = self._authorized()
        with patches[0], patches[1], patches[2], patch(
            "app.apis.KVrocksIndexer", return_value=indexer
        ), patch.object(
            IpQuickApi,
            "_resolve_window",
            return_value=(NOW - timedelta(days=30), NOW),
        ):
            client = app.test_client()
            self.assertEqual(client.get("/api/v1/ip-quick/1.1.1.1").status_code, 404)
            response = client.get("/api/v1/ip-quick/8.8.8.8")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["result"]["ports"], [])

    def test_invalid_ip_and_missing_auth(self):
        """Input is validated after FAB authentication, without backend reads."""
        self.assertIn(
            app.test_client().get("/api/v1/ip-quick/8.8.8.8").status_code,
            (401, 403),
        )
        patches = self._authorized()
        with patches[0], patches[1], patches[2], patch(
            "app.apis.KVrocksIndexer"
        ) as indexer:
            response = app.test_client().get("/api/v1/ip-quick/not-an-ip")
        self.assertEqual(response.status_code, 400)
        indexer.assert_not_called()

    def test_route_is_in_openapi_spec(self):
        """Swagger advertises the path, time controls and protected response."""
        with patch.object(appbuilder.sm, "has_access", return_value=True):
            response = app.test_client().get("/api/v1/_openapi")
        self.assertEqual(response.status_code, 200)
        endpoint = response.json["paths"]["/api/v1/ip-quick/{ip}"]["get"]
        self.assertEqual(
            endpoint["summary"], "Get open ports and tags observed for an IP."
        )
        self.assertEqual(
            {parameter["name"] for parameter in endpoint["parameters"]},
            {"ip", "days", "start", "stop"},
        )
        port_schema = endpoint["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["properties"]["result"]["properties"]["ports"]["items"]
        self.assertIn("last_seen", port_schema["properties"])
        self.assertNotIn("first_seen", port_schema["properties"])
