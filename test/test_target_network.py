"""Target enrichment regressions with isolated SQL and mocked CIRCL HTTP."""

# pylint: disable=protected-access
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_wtf.csrf import generate_csrf
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from app import app, db
from app.models import (
    Targets,
    AutonomousSystems,
    Jobs,
    Bots,
    ApiKeys,
    ScanProfiles,
    TargetScanStates,
)
from app.apis import PublicTargetsApi, Api
from app.utils import ip2asn, network_enrichment as enrichment
from app.views import TargetsView

NOW = datetime(2026, 9, 24, 12)
PAYLOAD = [
    {"country": {"iso_code": "US"}},
    {
        "country": {
            "iso_code": "US",
            "AutonomousSystemNumber": "214967",
            "AutonomousSystemOrganization": "OPTIBOUNCE",
        },
        "country_info": {
            "Alpha-3 code": "USA",
            "Numeric code": "840",
            "Latitude (average)": "38",
            "Longitude (average)": "-97",
        },
    },
]


class NetworkLookupTest(unittest.TestCase):
    """Address normalization and untrusted response validation."""

    def test_network_addresses_and_types(self):
        """Use network address for either family, including single hosts."""
        for value, address, kind in [
            ("192.0.2.34/24", "192.0.2.0", "IPv4 CIDR"),
            ("192.0.2.34/32", "192.0.2.34", "IPv4 CIDR"),
            ("2001:db8::34/64", "2001:db8::", "IPv6 CIDR"),
            ("2001:db8::34/128", "2001:db8::34", "IPv6 CIDR"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(ip2asn.network_address(value), address)
                self.assertEqual(ip2asn.target_type(value), kind)
        self.assertEqual(ip2asn.target_type("example.org"), "FQDN")

    def test_asn_entry_is_selected_and_country_numbers_keep_zeroes(self):
        """ASN data can occur after or before a country-only entry."""
        for payload in (PAYLOAD, list(reversed(PAYLOAD))):
            info = ip2asn.parse_network_information(payload)
            self.assertEqual(info["asn"], 214967)
            self.assertEqual(info["latitude"], 38)
            self.assertEqual(info["longitude"], -97)
        payload = [
            {"country": PAYLOAD[1]["country"], "country_info": {"Numeric code": "4"}}
        ]
        self.assertEqual(
            ip2asn.parse_network_information(payload)["country_numeric"], "004"
        )
        self.assertIsNone(ip2asn.parse_network_information(payload)["latitude"])

    def test_zero_asn_is_displayed_as_unannounced_cidr(self):
        """Render ASN zero as an unannounced CIDR instead of AS0."""
        target = Targets(value="192.0.2.0/24")
        target.autonomous_system = AutonomousSystems(asn=0, name="Reserved")
        self.assertEqual(target.network_asn_display, "CIDR not announced")

    def test_invalid_responses_do_not_fabricate_an_as(self):
        """Reject missing ASN/name, malformed arrays and non-finite coordinates."""
        for payload in (
            {},
            [],
            [{}],
            [{"country": {"AutonomousSystemNumber": "bad"}}],
            [
                {
                    "country": PAYLOAD[1]["country"],
                    "country_info": {"Latitude (average)": "nan"},
                }
            ],
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                ip2asn.parse_network_information(payload)

    def test_zero_asn_is_valid_for_unannounced_networks(self):
        """Accept CIRCL ASN zero for CIDRs that are not announced."""
        payload = [
            {
                "country": {
                    "iso_code": "US",
                    "AutonomousSystemNumber": 0,
                    "AutonomousSystemOrganization": "Not announced",
                },
                "country_info": {
                    "Alpha-3 code": "USA",
                    "Numeric code": "840",
                },
            }
        ]
        self.assertEqual(ip2asn.parse_network_information(payload)["asn"], 0)

    def test_http_uses_one_fixed_https_request_without_redirects(self):
        """No enumeration, hostname resolution or user-selected service URL."""
        with mock.patch.object(ip2asn.requests, "get") as get:
            get.return_value.status_code = 200
            get.return_value.json.return_value = PAYLOAD
            ip2asn.lookup_network_information("2001:db8::a/64")
            get.assert_called_once_with(
                "https://ip.circl.lu/geolookup/2001:db8::",
                timeout=10,
                allow_redirects=False,
            )
            get.reset_mock()
            self.assertEqual(
                ip2asn.get_asn_description_for_ip("example.org"),
                ip2asn.INVALID_NETWORK_MESSAGE,
            )
            get.assert_not_called()


class NetworkPersistenceTest(unittest.TestCase):
    """Refreshes claim work and persist without the scan writer transaction."""

    def setUp(self):
        """Use a separate file DB so competing sessions really are independent."""
        # unittest owns the context until all test/session cleanup has completed.
        # pylint: disable=consider-using-with
        self.folder = self.enterContext(tempfile.TemporaryDirectory())
        # pylint: enable=consider-using-with
        self.engine = create_engine(f"sqlite:///{self.folder}/test.db")
        self.addCleanup(self.engine.dispose)
        db.Model.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine)
        self.clock = mock.patch.object(enrichment, "utcnow_naive", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def add_target(self, value="192.0.2.0/24"):
        """Create as forms/API do, using model-level insertion defaults."""
        with self.factory() as session:
            target = Targets(value=value, description="Keep this description")
            session.add(target)
            session.commit()
            return target.id

    def refresh(self, target_id, force=False):
        """Refresh against this test's isolated database."""
        return enrichment.refresh_target_network(target_id, force, self.factory)

    def test_insert_scan_trigger_freshness_and_manual_override(self):
        """Initial queue, strict 24h boundary, and forced manual refresh."""
        target_id = self.add_target()
        with self.factory() as session:
            target = session.get(Targets, target_id)
            self.assertTrue(target.network_refresh_pending)
            self.assertIsNotNone(target.created_at)
            inserted = target.created_at
        with mock.patch.object(
            enrichment,
            "lookup_network_information",
            return_value=ip2asn.parse_network_information(PAYLOAD),
        ) as lookup:
            self.assertEqual(self.refresh(target_id), "updated")
            self.assertEqual(self.refresh(target_id), "fresh")
            self.assertEqual(lookup.call_count, 1)
            self.assertEqual(self.refresh(target_id, force=True), "updated")
            self.assertEqual(lookup.call_count, 2)
        with self.factory() as session:
            target = session.get(Targets, target_id)
            self.assertEqual(target.description, "Keep this description")
            self.assertEqual(target.created_at, inserted)
            self.assertEqual(target.as_bgp, 214967)
            self.assertEqual(target.as_description, "OPTIBOUNCE")
            enrichment.request_network_refresh(target, NOW + timedelta(hours=24))
            self.assertFalse(target.network_refresh_pending)
            enrichment.request_network_refresh(
                target, NOW + timedelta(hours=24, microseconds=1)
            )
            self.assertTrue(target.network_refresh_pending)

    def test_fqdn_does_not_queue_or_call_http(self):
        """FQDN insertion and manual refresh safely skip enrichment."""
        target_id = self.add_target("example.org")
        with mock.patch.object(enrichment, "lookup_network_information") as lookup:
            self.assertEqual(self.refresh(target_id, force=True), "unavailable")
            lookup.assert_not_called()
        with self.factory() as session:
            target = session.get(Targets, target_id)
            enrichment.request_network_refresh(target)
            self.assertFalse(target.network_refresh_pending)
            self.assertIsNone(target.network_asn)
            self.assertIn("Unavailable", target.network_information_html())

    def test_existing_as_is_shared_and_failed_refresh_preserves_good_data(self):
        """Missing/failed lookups cannot destroy known data or advance freshness."""
        first, second = self.add_target(), self.add_target("2001:db8::/64")
        with mock.patch.object(
            enrichment,
            "lookup_network_information",
            return_value=ip2asn.parse_network_information(PAYLOAD),
        ):
            self.refresh(first)
            self.refresh(second)
        with mock.patch.object(
            enrichment, "lookup_network_information", side_effect=requests.Timeout
        ):
            self.assertEqual(self.refresh(first, force=True), "failed")
        with self.factory() as session:
            self.assertEqual(session.query(AutonomousSystems).count(), 1)
            target = session.get(Targets, first)
            self.assertEqual(target.network_updated_at, NOW)
            self.assertEqual(target.network_asn, 214967)
            self.assertTrue(target.network_refresh_pending)

    def test_concurrent_refresh_claim_and_http_outside_writer_transaction(self):
        """A second worker skips the lease; independent writes can complete."""
        target_id = self.add_target()

        def during_http(_value, timeout):
            self.assertGreater(timeout, 0)
            self.assertEqual(self.refresh(target_id), "busy")
            with self.factory() as session:
                session.add(Targets(value="198.51.100.0/24"))
                session.commit()
            return ip2asn.parse_network_information(PAYLOAD)

        with mock.patch.object(
            enrichment, "lookup_network_information", side_effect=during_http
        ) as lookup:
            self.assertEqual(self.refresh(target_id), "updated")
            lookup.assert_called_once()

    def test_changed_target_during_lookup_does_not_receive_stale_as(self):
        """Editing a CIDR while HTTP runs invalidates its claim and association."""
        target_id = self.add_target()

        def change_value(_value, timeout):
            self.assertGreater(timeout, 0)
            with self.factory() as session:
                session.get(Targets, target_id).value = "example.org"
                session.commit()
            return ip2asn.parse_network_information(PAYLOAD)

        with mock.patch.object(
            enrichment, "lookup_network_information", side_effect=change_value
        ):
            self.assertEqual(self.refresh(target_id), "superseded")
        with self.factory() as session:
            self.assertIsNone(session.get(Targets, target_id).network_asn)

    def test_expired_lease_is_recoverable_and_as_assignment_can_change(self):
        """A crashed worker cannot block future refreshes; ASN changes are saved."""
        target_id = self.add_target()
        with self.factory() as session:
            target = session.get(Targets, target_id)
            target.network_claim = "abandoned"
            target.network_claim_until = NOW - timedelta(seconds=1)
            session.commit()
        info = ip2asn.parse_network_information(PAYLOAD)
        with mock.patch.object(
            enrichment, "lookup_network_information", return_value=info
        ):
            self.assertEqual(self.refresh(target_id), "updated")
        changed = {**info, "asn": 6661, "name": "<script>bad</script>"}
        with mock.patch.object(
            enrichment, "lookup_network_information", return_value=changed
        ):
            self.assertEqual(self.refresh(target_id, force=True), "updated")
        with self.factory() as session:
            target = session.get(Targets, target_id)
            self.assertEqual(target.network_asn, 6661)
            self.assertNotIn("<script>", target.network_information_html())
            self.assertEqual(session.query(AutonomousSystems).count(), 2)

    def test_pending_worker_uses_durable_insertion_queue(self):
        """The independent scheduler consumes pending CIDRs, skipping FQDNs."""
        target_id = self.add_target()
        self.add_target("example.org")
        with mock.patch.object(
            enrichment, "sessionmaker", return_value=self.factory
        ), mock.patch.object(
            enrichment,
            "lookup_network_information",
            return_value=ip2asn.parse_network_information(PAYLOAD),
        ) as lookup:
            enrichment.process_pending_network_refreshes()
            lookup.assert_called_once()
        with self.factory() as session:
            self.assertEqual(session.get(Targets, target_id).network_asn, 214967)
            self.assertFalse(session.get(Targets, target_id).network_refresh_pending)

    def test_gui_bulk_and_single_api_insert_share_metadata(self):
        """Both tool API paths use model insertion defaults and preserve descriptions."""
        api = next(
            item
            for item in app.appbuilder.baseviews
            if isinstance(item, PublicTargetsApi)
        )
        with app.app_context(), self.factory() as session, mock.patch.object(
            db, "session", session
        ), mock.patch.object(api.datamodel, "session", session), mock.patch.object(
            enrichment, "lookup_network_information"
        ) as lookup:
            TargetsView.do_bulk_import("9.9.9.0/24\rexample.org")
            with app.test_request_context(
                "/",
                method="POST",
                json={
                    "value": "2001:db8::/64",
                    "description": "Imported by tool",
                    "active": True,
                    "priority": 3,
                },
            ):
                response = api.post_headless()
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.json["result"]["target_type"], "IPv6 CIDR")
                self.assertTrue(response.json["result"]["network_refresh_pending"])
                self.assertTrue(response.json["result"]["created_at"].endswith("Z"))
            targets = session.query(Targets).order_by(Targets.id).all()
            self.assertEqual(
                [target.network_refresh_pending for target in targets],
                [True, False, True],
            )
            self.assertEqual(targets[-1].description, "Imported by tool")
            self.assertEqual(targets[-1].priority, 3)
            self.assertTrue(all(target.created_at for target in targets))
            lookup.assert_not_called()

    def test_target_detail_renders_metadata_and_permission_aware_refresh(self):
        """Render the real detail template, including its protected CSRF form."""
        target_id = self.add_target()
        view = next(
            item for item in app.appbuilder.baseviews if isinstance(item, TargetsView)
        )
        with app.app_context(), self.factory() as session, mock.patch.object(
            db, "session", session
        ), mock.patch.object(view.datamodel, "session", session):
            for allowed in (True, False):
                with app.test_request_context("/"), mock.patch.object(
                    app.appbuilder.sm,
                    "has_access",
                    side_effect=lambda permission, _view, allowed=allowed: permission
                    != "can_refresh_network"
                    or allowed,
                ):
                    html = view.show(target_id)
                    self.assertIn("IPv4 CIDR", html)
                    self.assertIn("Keep this description", html)
                    self.assertIn("Inserted at (UTC)", html)
                    self.assertEqual(
                        f"/targetsview/refresh_network/{target_id}" in html, allowed
                    )

    def test_scan_receipt_queues_stale_metadata_before_sibling_jobs_finish(self):
        """Successful authenticated scan receipt queues independently of target completion."""
        target_id = self.add_target()
        folder = Path(self.folder) / "jsons"
        (folder / "1").mkdir(parents=True)
        agent_key = "a" * 80
        with app.app_context(), self.factory() as session:
            bot = Bots(
                uid="22222222-2222-4222-8222-222222222222",
                ip="8.8.8.8",
                country="US",
                device_model="test",
                agent_version="test",
                system_version="test",
            )
            profile = ScanProfiles(name="test", scan_cycle_minutes=1440)
            target = session.get(Targets, target_id)
            target.network_refresh_pending = False
            target.last_scan = NOW - timedelta(days=2)
            session.add_all(
                [
                    bot,
                    profile,
                    ApiKeys(
                        keyidx=agent_key[:16],
                        key=generate_password_hash(
                            agent_key, method="pbkdf2:sha256:1000"
                        ),
                        description="test",
                    ),
                ]
            )
            session.flush()
            state = TargetScanStates(target=target, scanprofile=profile, working=True)
            jobs = [
                Jobs(
                    uid=f"11111111-1111-4111-8111-11111111111{number}",
                    job=target.value,
                    targets=[target],
                    scanprofile=profile,
                    bot_id=bot.id,
                    active=True,
                    job_start=NOW - timedelta(minutes=5),
                )
                for number in (1, 2)
            ]
            session.add_all([state, *jobs])
            session.commit()
            payload = {
                "UID": bot.uid,
                "AGENT_KEY": agent_key,
                "JOB_UID": jobs[0].uid,
                "DEVICE_MODEL": "test",
                "AGENT_VERSION": "test",
                "SYSTEM_VERSION": "test",
                "EXT_IP": "8.8.8.8",
                "RESULT": "{}",
            }
            with mock.patch.object(db, "session", session), mock.patch.dict(
                app.config, {"JSON_FOLDER": str(folder)}
            ), app.test_request_context(
                "/bot_api/sndjob", method="POST", json=payload
            ), mock.patch.object(
                enrichment, "lookup_network_information"
            ) as lookup:
                response = Api().sndjobs()
                self.assertEqual(response.status_code, 200)
                self.assertTrue(session.get(Targets, target_id).network_refresh_pending)
                self.assertTrue(state.working)
                self.assertFalse(jobs[1].finished)
                self.assertTrue(jobs[0].finished)
                lookup.assert_not_called()


class NetworkRefreshAccessTest(unittest.TestCase):
    """Protect detail and existing bulk action against direct mutation calls."""

    def test_fab_permission_decorator_is_present(self):
        """FAB registers a separate permission and POST-only route."""
        self.assertEqual(
            TargetsView.refresh_network._permission_name, "refresh_network"
        )
        self.assertIn(
            ("/refresh_network/<int:pk>", ["POST"]), TargetsView.refresh_network._urls
        )

    def test_csrf_and_method_are_checked(self):
        """No refresh is allowed through GET or missing CSRF token."""
        for method, status in (("GET", 405), ("POST", 400)):
            with app.test_request_context("/", method=method):
                with self.assertRaises(HTTPException) as error:
                    TargetsView._validate_network_refresh_request()
                self.assertEqual(error.exception.code, status)
        with app.test_request_context("/", method="POST"):
            token = generate_csrf()
            with mock.patch("app.views.request", new=mock.Mock()) as request:
                request.method = "POST"
                request.form.get.return_value = token
                TargetsView._validate_network_refresh_request()

    def test_bulk_action_denies_unprivileged_caller(self):
        """Even direct action invocation checks its existing FAB permission."""
        view = TargetsView()
        view.appbuilder = mock.Mock()
        view.appbuilder.sm.has_access.return_value = False
        with app.test_request_context("/", method="POST"), mock.patch(
            "app.views.refresh_target_network"
        ) as refresh:
            with self.assertRaises(HTTPException) as error:
                view.mulrreslovewhois([])
            self.assertEqual(error.exception.code, 403)
            refresh.assert_not_called()

    def test_detail_route_rejects_direct_unauthorized_request(self):
        """The registered route enforces FAB before attempting network access."""
        with mock.patch.object(
            app.appbuilder.sm, "has_access", return_value=False
        ), mock.patch("app.views.refresh_target_network") as refresh:
            response = app.test_client().post("/targetsview/refresh_network/1")
            self.assertIn(response.status_code, (302, 403))
            refresh.assert_not_called()

    def test_authorized_detail_post_forces_lookup(self):
        """Allowed users with CSRF can force a detail refresh."""
        view = next(
            item for item in app.appbuilder.baseviews if isinstance(item, TargetsView)
        )
        with app.test_request_context("/", method="POST"):
            token = generate_csrf()
            with mock.patch(
                "app.views.request",
                new=mock.Mock(method="POST", form={"csrf_token": token}),
            ), mock.patch.object(
                view.datamodel, "get", return_value=mock.Mock(id=1)
            ), mock.patch.object(
                app.appbuilder.sm, "has_access", return_value=True
            ), mock.patch(
                "app.views.refresh_target_network", return_value="updated"
            ) as refresh:
                response = view.refresh_network(1)
                self.assertEqual(response.status_code, 302)
                refresh.assert_called_once_with(1, force=True)


class NetworkMigrationTest(unittest.TestCase):
    """History-derived timestamps and a migration safe to rerun."""

    def setUp(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "webapp/sql_upd/23_migrate_from_4eb42ebc9bf251ffc5a563554967d1450d678df2.py"
        )
        spec = importlib.util.spec_from_file_location("target_network_migration", path)
        self.migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.migration)
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.executescript("""
            CREATE TABLE targets (id INTEGER PRIMARY KEY, value TEXT, description TEXT,
                last_scan DATETIME, last_previous_scan DATETIME, as_bgp INTEGER,
                as_description TEXT, as_country TEXT);
            CREATE TABLE jobs (id INTEGER PRIMARY KEY, finished BOOLEAN, job_start DATETIME,
                job_end DATETIME, job_creation DATETIME);
            CREATE TABLE jobs_targets_assoc (job_id INTEGER, target_id INTEGER);
            INSERT INTO targets VALUES (1, '192.0.2.0/24', 'keep', '2026-09-23', '2026-09-20',
                214967, 'OPTIBOUNCE', 'US'), (2, 'example.org', 'keep fqdn', NULL, NULL, 0, NULL, NULL);
            INSERT INTO jobs VALUES (1, 1, '2026-09-01', '2026-09-02', '2026-08-01'),
                (2, 1, '2026-09-10', '2026-09-11', '2026-08-01');
            INSERT INTO jobs_targets_assoc VALUES (1, 1), (2, 1);
        """)

    def test_oldest_scan_fallback_legacy_as_and_rerun(self):
        """Use earliest completed scan (not job creation), else migration now."""
        self.migration.migrate(self.connection, now=NOW)
        before = self.connection.execute(
            "SELECT id, created_at, description, network_asn FROM targets ORDER BY id"
        ).fetchall()
        self.assertEqual(before[0], (1, "2026-09-01 00:00:00", "keep", 214967))
        self.assertEqual(before[1], (2, str(NOW), "keep fqdn", None))
        self.migration.migrate(self.connection, now=NOW + timedelta(days=2))
        self.assertEqual(
            before,
            self.connection.execute(
                "SELECT id, created_at, description, network_asn FROM targets ORDER BY id"
            ).fetchall(),
        )

    def test_exported_history_supplies_older_dates_for_cidr_and_fqdn(self):
        """Supplement purged SQL history using a retained history CSV."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "history.csv"
            path.write_text(
                "target,ip,first_seen\n,192.0.2.42,2025-01-01T00:00:00Z\nexample.org,,2025-02-01T00:00:00Z\n",
                encoding="utf-8",
            )
            self.migration.migrate(self.connection, now=NOW, history_csv=path)
        dates = self.connection.execute(
            "SELECT created_at FROM targets ORDER BY id"
        ).fetchall()
        self.assertEqual(dates, [("2025-01-01 00:00:00",), ("2025-02-01 00:00:00",)])

    def test_dry_run_leaves_database_bytes_unchanged(self):
        """The migration CLI uses a disposable copy for its dry run."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.db"
            target = sqlite3.connect(path)
            self.connection.backup(target)
            target.close()
            before = path.read_bytes()
            result = subprocess.run(
                [
                    sys.executable,
                    self.migration.__file__,
                    "--db",
                    str(path),
                    "--dry-run",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertIn("DRY RUN", result.stdout)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
