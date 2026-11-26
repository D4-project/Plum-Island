"""Shared lookup cache expiry, failures, concurrency and consumer boundaries."""

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import redis

from app import app, appbuilder
from app.views import TargetsView
from app.utils.ip2asn import lookup_network_information
from app.utils.lookup_cache import ResponseCache, LookupBusy
from app.utils import enrichment_cache as sources
from app.utils.reports import collect_report_passive_dns_fqdns
from app.utils.resolved_export import lookup_pdns


class MemoryRedis:
    """Small expiring store implementing the cache's atomic Redis contracts."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.values = {}
        self.mutex = threading.RLock()

    def get(self, key):
        """Return only unexpired values."""
        with self.mutex:
            value, expires = self.values.get(key, (None, 0))
            return value if self.clock() < expires else None

    def set(self, key, value, ex):
        """Atomically store a value with fixed lifetime."""
        with self.mutex:
            self.values[key] = (value, self.clock() + ex)

    def lock(self, key, timeout, blocking_timeout):
        """Create an ownership-checked test lease."""
        store = self
        token = uuid4().hex

        class Lease:
            """Expire owners and release only the acquired token."""

            def __init__(self):
                self.local = SimpleNamespace(token=token)

            def acquire(self):
                """Wait until available or deadline reached."""
                deadline = time.monotonic() + blocking_timeout
                while True:
                    with store.mutex:
                        if store.get(key) is None:
                            store.set(key, token, timeout)
                            return True
                    if time.monotonic() >= deadline:
                        return False
                    time.sleep(0.005)

            def release(self):
                """Never release another owner."""
                with store.mutex:
                    if store.get(key) != token:
                        raise redis.exceptions.LockNotOwnedError()
                    store.values.pop(key, None)

        return Lease()

    def eval(
        self, _script, _count, lock_key, key, token, payload, ttl
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        """Implement the atomic owner-checked publish contract."""
        with self.mutex:
            if self.get(lock_key) == token:
                self.set(key, payload, ttl)
                return True
        return None


class LookupCacheTest(unittest.TestCase):
    """Use a controllable clock and no external backends or registries."""

    def setUp(self):
        self.now = 1000
        self.backend = MemoryRedis(lambda: self.now)
        self.cache = ResponseCache(self.backend, lambda: self.now)

    def test_expiry_from_completion_without_access_or_sliding_reads(self):
        """Expiry from completion without access or sliding reads."""

        def retrieve():
            self.now += 5
            return "record"

        loader = Mock(side_effect=retrieve)
        first = self.cache.get("whois:8.8.8.8/32", 86400, loader, 10)
        self.assertEqual(first["fetched_at"], 1005)
        self.now = 87404
        hit = self.cache.get("whois:8.8.8.8/32", 86400, loader, 10)
        self.assertTrue(hit["cached"])
        self.assertEqual(hit["expires_at"], 87405)
        self.now = 87405
        self.assertIsNone(self.backend.get("plum:lookup:v1:whois:8.8.8.8/32:ttl:86400"))
        self.assertFalse(
            self.cache.get("whois:8.8.8.8/32", 86400, loader, 10)["cached"]
        )
        self.assertEqual(loader.call_count, 2)

    def test_failure_not_cached_and_lease_released(self):
        """Failure not cached and lease released."""
        loader = Mock(side_effect=[LookupError("offline"), "recovered"])
        with self.assertRaises(LookupError):
            self.cache.get("key", 100, loader, 1)
        self.assertEqual(self.cache.get("key", 100, loader, 1)["value"], "recovered")

    def test_corrupt_or_expired_record_is_refetched(self):
        """Corrupt or expired record is refetched."""
        key = "plum:lookup:v1:key:ttl:100"
        for value in (
            "not JSON",
            "[]",
            '{"fetched_at": 1}',
            json.dumps({"fetched_at": 1, "expires_at": 101, "value": "old"}),
        ):
            with self.subTest(value=value):
                self.backend.set(key, value, 1000)
                self.assertFalse(self.cache.get("key", 100, lambda: "new", 1)["cached"])

    def test_outage_falls_back_without_hiding_resolver_errors(self):
        """Outage falls back without hiding resolver errors."""
        backend = Mock()
        backend.get.side_effect = redis.ConnectionError()
        cache = ResponseCache(backend)
        self.assertEqual(cache.get("key", 100, lambda: "live", 1)["value"], "live")
        with self.assertRaisesRegex(LookupError, "source"):
            cache.get("key", 100, Mock(side_effect=LookupError("source")), 1)

    def test_expired_owner_cannot_publish_or_release_successor(self):
        """Expired owner cannot publish or release successor."""
        lock_key = "plum:lookup:v1:key:ttl:100:lock"

        def retrieve():
            self.now += 2
            self.backend.set(lock_key, "successor", 10)
            return "old response"

        self.cache.get("key", 100, retrieve, 1)
        self.assertEqual(self.backend.get(lock_key), "successor")
        self.assertIsNone(self.backend.get(lock_key[:-5]))

    def test_concurrent_misses_share_result_across_instances(self):
        """Concurrent misses share result across instances."""
        entered = threading.Event()
        finish = threading.Event()

        def retrieve():
            entered.set()
            self.assertTrue(finish.wait(2))
            return "shared"

        loader = Mock(side_effect=retrieve)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.cache.get, "key", 100, loader, 2)
            self.assertTrue(entered.wait(2))
            other = ResponseCache(self.backend, lambda: self.now)
            second = pool.submit(other.get, "key", 100, loader, 2)
            finish.set()
            self.assertEqual(first.result()["value"], "shared")
            self.assertEqual(second.result()["value"], "shared")
        loader.assert_called_once()

    def test_busy_wait_is_bounded_and_does_not_duplicate_work(self):
        """Busy wait is bounded and does not duplicate work."""
        self.backend.set("plum:lookup:v1:key:ttl:100:lock", "owner", 100)
        loader = Mock()
        with self.assertRaises(LookupBusy):
            self.cache.get("key", 100, loader, 0.01)
        loader.assert_not_called()

    def test_force_and_lifetime_change_bypass_existing_value(self):
        """Force and lifetime change bypass existing value."""
        loader = Mock(side_effect=["first", "forced", "new policy"])
        self.cache.get("key", 100, loader, 1)
        self.assertEqual(
            self.cache.get("key", 100, loader, 1, force=True)["value"], "forced"
        )
        self.assertEqual(self.cache.get("key", 200, loader, 1)["value"], "new policy")

    def test_whois_canonical_identity_and_distinct_networks(self):
        """Whois canonical identity and distinct networks."""
        with patch(
            "app.utils.lookup_cache.cache_client", return_value=MemoryRedis()
        ), patch.object(
            sources, "lookup_network_whois", return_value="record"
        ) as source:
            sources.network_whois("2001:0db8::1")
            self.assertTrue(sources.network_whois("2001:db8::1/128")["cached"])
            sources.network_whois("2001:db8::/64")
            self.assertEqual(source.call_count, 2)

    def test_pdns_shared_by_ui_reports_exports_and_isolated_by_credentials(self):
        """Pdns shared by ui reports exports and isolated by credentials."""
        records = [
            {
                "rrtype": "A",
                "rrname": "host.example.org",
                "rdata": "8.8.8.8",
                "time_first": 100,
                "time_last": 200,
            }
        ]
        backend = MemoryRedis()
        with app.app_context(), patch.dict(
            app.config,
            PASSIVE_USER="cache-test",
            PASSIVE_PWD="password",
            PDNS_ENABLED=True,
        ), patch(
            "app.utils.lookup_cache.cache_client", return_value=backend
        ), patch.object(
            sources, "_pdns_source", return_value=records
        ) as upstream, patch.object(
            appbuilder.sm, "has_access", return_value=True
        ):
            response = app.test_client().get("/ip/pdns/8.8.8.8")
            self.assertEqual(response.status_code, 200)
            self.assertIn("resolve_token", response.json[0])
            report = collect_report_passive_dns_fqdns(app.config, ["8.8.8.8"], {})
            self.assertEqual(report["8.8.8.8"][0]["fqdn"], "host.example.org")
            self.assertEqual(
                lookup_pdns(
                    "8.8.8.8", "cache-test", "password", {"from_ts": 100, "to_ts": 200}
                ),
                ["host.example.org"],
            )
            upstream.assert_called_once()
            sources.passive_dns("8.8.8.8", "cache-test", "changed-password")
            self.assertEqual(upstream.call_count, 2)
            self.assertNotIn("password", repr(backend.values))
            stored = [
                json.loads(value[0])
                for key, value in backend.values.items()
                if not key.endswith(":lock")
            ]
            self.assertNotIn("resolve_token", repr(stored))
            self.assertEqual(stored[0]["expires_at"] - stored[0]["fetched_at"], 43200)

    def test_target_and_ip_views_share_source_and_preserve_show_permissions(self):
        """Target GET uses row filters and show permission, sharing geolocation."""

        view = next(
            view for view in appbuilder.baseviews if isinstance(view, TargetsView)
        )
        source_payload = [
            {
                "country": {
                    "AutonomousSystemNumber": 64500,
                    "AutonomousSystemOrganization": "Example AS",
                }
            }
        ]
        backend = MemoryRedis()
        with app.app_context(), patch(
            "app.utils.lookup_cache.cache_client", return_value=backend
        ), patch(
            "app.utils.enrichment_cache.fetch_network_payload",
            return_value=source_payload,
        ) as upstream, patch.object(
            view.datamodel, "get", return_value=SimpleNamespace(value="8.8.8.8")
        ) as row, patch.object(
            appbuilder.sm, "has_access", return_value=True
        ) as access:
            client = app.test_client()
            self.assertEqual(client.get("/ip/geolookup/8.8.8.8").status_code, 200)
            response = client.get("/targetsview/network_info/123")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["info"]["asn"], 64500)
            self.assertTrue(response.json["cache"]["cached"])
            access.assert_any_call("can_show", "TargetsView")
            # pylint: disable=protected-access
            row.assert_called_with(
                123, view._base_filters
            )  # pylint: disable=protected-access
            upstream.assert_called_once()
            access.return_value = False
            self.assertIn(
                client.get("/targetsview/network_info/123").status_code, (302, 403)
            )
            upstream.assert_called_once()

    def test_cached_snapshot_keeps_source_age_and_force_refreshes(self):
        """SQL enrichment must not treat an old cache hit as newly fetched data."""

        payload = [
            {
                "country": {
                    "AutonomousSystemNumber": 64500,
                    "AutonomousSystemOrganization": "Example AS",
                }
            }
        ]
        with app.app_context(), patch(
            "app.utils.lookup_cache.cache_client", return_value=MemoryRedis()
        ), patch(
            "app.utils.enrichment_cache.fetch_network_payload", return_value=payload
        ) as upstream:
            first = lookup_network_information("8.8.8.8")
            second = lookup_network_information("8.8.8.8")
            self.assertEqual(first.fetched_at, second.fetched_at)
            upstream.assert_called_once()
            lookup_network_information("8.8.8.8", force=True)
            self.assertEqual(upstream.call_count, 2)
