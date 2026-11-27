"""Filtered search observations become durable target and port groups."""

import runpy
import sqlite3
import unittest
import uuid
import fnmatch
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from flask import Flask
from flask_appbuilder import SQLA
from flask_appbuilder.models.sqla.interface import SQLAInterface
from sqlalchemy import event, text

from app import views
from app.models import (
    FilteredScanTargets,
    Jobs,
    ScanProfileCycles,
    ScanProfiles,
    Targets,
)
from app.utils import filtered_scans, scan_cycles
from app.utils.filtered_work import FilteredWorkStore
from app.utils.tagrules import compile_tag_rule_definition, validate_search_query
from test.test_scanprofile_api import ProfileApiFixture


class MemoryPipeline:
    """Small Redis pipeline used by filtered preparation tests."""

    def __init__(self, store):
        self.store = store
        self.calls = []

    def __getattr__(self, name):
        def queue(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self

        return queue

    def execute(self):
        result = [
            getattr(self.store, name)(*args, **kwargs)
            for name, args, kwargs in self.calls
        ]
        self.calls.clear()
        return result


class MemoryRedis:
    """Redis hash and sorted-set semantics needed by filtered work."""

    def __init__(self):
        self.data = {}

    def pipeline(self, **_kwargs):
        return MemoryPipeline(self)

    def delete(self, *keys):
        for key in keys:
            self.data.pop(key, None)

    def hset(self, key, field=None, value=None, mapping=None):
        target = self.data.setdefault(key, {})
        if mapping:
            target.update({str(k): str(v) for k, v in mapping.items()})
        elif field is not None:
            target[str(field)] = str(value)

    def hsetnx(self, key, field, value):
        target = self.data.setdefault(key, {})
        if str(field) in target:
            return 0
        target[str(field)] = str(value)
        return 1

    def hget(self, key, field):
        return self.data.get(key, {}).get(str(field))

    def hgetall(self, key):
        return dict(self.data.get(key, {}))

    def hkeys(self, key):
        return list(self.data.get(key, {}))

    def hlen(self, key):
        return len(self.data.get(key, {}))

    def hdel(self, key, *fields):
        for field in fields:
            self.data.get(key, {}).pop(str(field), None)

    def hscan(self, key, cursor=0, count=10):
        items = list(self.data.get(key, {}).items())
        end = min(len(items), int(cursor) + count)
        return (0 if end == len(items) else end), dict(items[int(cursor) : end])

    def zadd(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)

    def zrange(self, key, start, end):
        values = sorted(self.data.get(key, {}))
        return values[start:] if end < 0 else values[start : end + 1]

    def zrem(self, key, *members):
        for member in members:
            self.data.get(key, {}).pop(member, None)

    def zcard(self, key):
        return len(self.data.get(key, {}))

    def scan_iter(self, match, **_kwargs):
        return iter(key for key in self.data if fnmatch.fnmatchcase(key, match))


class FilteredScanPreparationTest(unittest.TestCase):
    """Exercise extraction without live Kvrocks or Meilisearch."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite://",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            KVROCKS_HOST="unused.test",
            KVROCKS_PORT=6666,
            TLDADD=[],
            HTTP_HEADER_COLLECTION={},
        )
        self.enterContext(self.app.app_context())
        self.db = SQLA(self.app)
        self.db.create_all()
        self.enterContext(patch.object(filtered_scans, "db", self.db))
        self.redis = MemoryRedis()
        self.indexer = Mock(raw=self.redis, r=self.redis)
        self.indexer.get_requested_hostnames_for_uids.return_value = {}
        self.enterContext(
            patch.object(filtered_scans, "KVrocksIndexer", return_value=self.indexer)
        )

        target = Targets(value="8.8.8.8", is_ip_cidr=True)
        profile = ScanProfiles(
            name="filtered",
            search_query="banner.lk:hello",
            filter_revision=1,
            filter_enabled=True,
            apply_to_all=False,
        )
        cycle = ScanProfileCycles(
            scanprofile=profile,
            status="running",
            filter_revision=1,
            preparation_status="pending",
            filter_query=profile.search_query,
            filter_from_ts=10,
            filter_to_ts=20,
        )
        self.db.session.add_all([target, cycle])
        self.db.session.commit()
        self.cycle_id = cycle.id

    @staticmethod
    def observation_batches(uids):
        """Represent one paged index candidate at a time for the fallback tests."""
        for uid in uids:
            yield None, [(uid, "8.8.8.8", {})]

    @staticmethod
    def chronological_batches(uids):
        """Represent time-ordered pages with replay cursors."""
        for offset, uid in enumerate(uids, start=1):
            yield None, [(uid, "8.8.8.8", {})], (20 - offset, 1), 1

    @staticmethod
    def document(uid, port):
        """Return one port-scoped historical report."""
        return {
            "id": uid,
            "ip": "8.8.8.8",
            "body": {
                "endtime": 15,
                "hostnames": [],
                "ports": [
                    {
                        "protocol": "tcp",
                        "portid": str(port),
                        "state": {"state": "open"},
                        "scripts": [{"id": "banner", "output": "hello service"}],
                    }
                ],
            },
        }

    def test_missing_open_state_is_rejected(self):
        """Unknown state must not become an open-port candidate."""
        document = self.document("unknown", 443)
        document["body"]["ports"][0].pop("state")
        self.assertEqual(
            filtered_scans._matching_ports(
                document, validate_search_query("banner.lk:hello"), [], self.app.config
            ),
            set(),
        )

    def test_nodata_selects_only_open_tcp_ports_without_details(self):
        """Use open-only observations as port evidence in filtered profiles."""
        document = self.document("nodata", 443)
        document["body"]["ports"].extend(
            [
                {
                    "portid": "30",
                    "protocol": "tcp",
                    "state": {"state": "open", "reason_ttl": "0"},
                },
                {"portid": "31", "protocol": "tcp", "state": {"state": "closed"}},
                {"portid": "53", "protocol": "udp", "state": {"state": "open"}},
            ]
        )
        for query, expected in (
            ("nodata", {30}),
            ("nodata:30", {30}),
            ("nodata:443", set()),
        ):
            with self.subTest(query=query):
                historical_query = f"{query} since:90"
                self.assertEqual(
                    views.validate_profile_search_query(
                        historical_query, require_candidate=False
                    ),
                    historical_query,
                )
                criteria = validate_search_query(query)
                self.assertTrue(filtered_scans.query_can_prove_port(criteria))
                self.assertEqual(
                    filtered_scans._matching_ports(
                        document, criteria, [], self.app.config
                    ),
                    expected,
                )

    def test_frequency_uses_start_and_never_overlaps(self):
        """A slow tour restarts once finished, without another full delay."""
        cycle = self.db.session.get(ScanProfileCycles, self.cycle_id)
        profile = cycle.scanprofile
        now = datetime(2026, 11, 22, 12)
        profile.scan_cycle_minutes = 60
        cycle.started_at = now - timedelta(minutes=80)
        self.db.session.commit()
        search = Mock()
        search._extract_since_days.return_value = (30, True, None)
        search._resolve_since_time_range.return_value = (
            {"from_ts": 10, "to_ts": 20},
            True,
            None,
        )
        with patch.object(filtered_scans, "utcnow_naive", return_value=now):
            self.assertIsNone(filtered_scans.start_due_cycle(profile, search))
            cycle.status = "finished"
            cycle.finished_at = now
            profile.last_cycle_finished_at = now
            self.db.session.commit()
            self.assertIsNotNone(filtered_scans.start_due_cycle(profile, search))

    def test_same_target_ports_are_merged_and_retry_is_idempotent(self):
        """Repeated observations merge ports into one Kvrocks candidate."""
        meili = Mock()
        meili.get_document.side_effect = [
            self.document("u80", 80),
            self.document("u443", 443),
            self.document("u80", 80),
            self.document("u443", 443),
        ]
        with patch.object(
            filtered_scans,
            "chronological_observation_batches",
            side_effect=lambda *_args, **_kwargs: self.chronological_batches(
                ["u80", "u443"]
            ),
        ), patch.object(filtered_scans, "proven_indexed_ports", return_value={}):
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, meili), 1)
            cycle = self.db.session.get(ScanProfileCycles, self.cycle_id)
            cycle.preparation_status = "pending"
            self.db.session.commit()
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, meili), 1)

        self.assertEqual(self.db.session.query(FilteredScanTargets).count(), 0)
        store = FilteredWorkStore(self.redis, self.cycle_id, 1)
        self.assertEqual(store.counts()["retained"], 1)
        self.assertEqual(store.groups()[0][1]["ports"], "80,443")
        self.assertEqual(
            self.db.session.get(ScanProfileCycles, self.cycle_id).preparation_status,
            "ready",
        )

    def test_backend_reads_do_not_hold_a_sql_transaction_between_batches(self):
        """Even slow backend reads run outside every SQLite writer transaction."""
        ports = {"u80": 80, "u443": 443, "u8443": 8443}
        session = self.db.session()

        def next_uid(*_args, **_kwargs):
            for offset, uid in enumerate(ports, start=1):
                self.assertFalse(session.in_transaction())
                yield None, [(uid, "8.8.8.8", {})], (20 - offset, 1), 1

        def read_report(uid):
            self.assertFalse(session.in_transaction())
            return self.document(uid, ports[uid])

        meili = Mock()
        meili.get_document.side_effect = read_report
        with (
            patch.object(filtered_scans, "chronological_observation_batches", next_uid),
            patch.object(filtered_scans, "proven_indexed_ports", return_value={}),
        ):
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, meili), 1)
        self.assertFalse(session.in_transaction())
        self.assertEqual(session.query(FilteredScanTargets).count(), 0)
        store = FilteredWorkStore(self.redis, self.cycle_id, 1)
        self.assertEqual(store.groups()[0][1]["ports"], "80,443,8443")

    def test_candidate_volume_does_not_add_sql_writes(self):
        """Collection writes cycle state only, regardless of candidate count."""
        target_id = self.db.session.query(Targets.id).scalar()
        statements = Counter()

        def count_writes(_conn, _cursor, statement, _params, _context, _many):
            verb = statement.lstrip().split(None, 1)[0].upper()
            if verb in {"INSERT", "UPDATE", "DELETE"}:
                statements[verb] += 1

        event.listen(self.db.engine, "before_cursor_execute", count_writes)

        def pages(*_args, **_kwargs):
            for offset in range(100):
                yield None, [(f"u{offset}", "8.8.8.8", {})], (20 - offset / 1000, 1), 1

        def candidates(_indexer, _meili, _plan, observations, *_args):
            uid = observations[0][0]
            return [(target_id, "fqdn", f"{uid}.example.org", {443})]

        with patch.object(
            filtered_scans, "chronological_observation_batches", pages
        ), patch.object(filtered_scans, "_page_candidates", candidates):
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, Mock()), 100)
        self.assertEqual(self.db.session.query(FilteredScanTargets).count(), 0)
        self.assertEqual(statements["INSERT"], 0)
        self.assertLessEqual(statements["UPDATE"], 2)

    def test_profile_edit_during_backend_read_discards_unwritten_batch(self):
        """A stale extraction cannot publish or persist its final batch."""
        ports = {"u80": 80, "u443": 443, "u8443": 8443}

        def read_report(uid):
            if uid == "u8443":
                profile = self.db.session.query(ScanProfiles).one()
                profile.filter_revision += 1
                self.db.session.commit()
            return self.document(uid, ports[uid])

        meili = Mock()
        meili.get_document.side_effect = read_report
        with (
            patch.object(
                filtered_scans,
                "chronological_observation_batches",
                return_value=self.chronological_batches(ports),
            ),
            patch.object(filtered_scans, "proven_indexed_ports", return_value={}),
        ):
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, meili), 1)
        cycle = self.db.session.get(ScanProfileCycles, self.cycle_id)
        self.assertEqual(cycle.preparation_status, "cancelled")
        self.assertEqual(self.db.session.query(FilteredScanTargets).count(), 0)

    def test_retry_resumes_after_the_last_committed_kvrocks_page(self):
        """A failed read keeps collected work and resumes at its saved cursor."""
        cycle = self.db.session.get(ScanProfileCycles, self.cycle_id)
        meili = Mock()
        meili.get_document.side_effect = [
            self.document("u80", 80),
            self.document("u443", 443),
        ]

        def interrupted(*_args, **_kwargs):
            yield from self.chronological_batches(["u80"])
            raise TimeoutError("test timeout")

        with (
            patch.object(
                filtered_scans,
                "chronological_observation_batches",
                side_effect=[
                    interrupted(),
                    self.chronological_batches(["u443"]),
                ],
            ),
            patch.object(filtered_scans, "proven_indexed_ports", return_value={}),
        ):
            with self.assertRaises(TimeoutError):
                filtered_scans.prepare_cycle(self.cycle_id, meili)
            self.assertEqual(cycle.preparation_status, "retry")
            self.assertEqual(filtered_scans.prepare_cycle(self.cycle_id, meili), 1)
        store = FilteredWorkStore(self.redis, self.cycle_id, 1)
        self.assertEqual(store.groups()[0][1]["ports"], "80,443")
        self.assertEqual(store.checkpoint(), (19.0, 1))
        self.assertEqual(cycle.preparation_status, "ready")

    def test_tag_proof_selects_only_contributing_port(self):
        """A service tag must retain its producing port, not sibling ports."""
        document = {
            "id": "multi",
            "ip": "8.8.8.8",
            "body": {
                "endtime": 15,
                "hostnames": [],
                "ports": [
                    {
                        "protocol": "tcp",
                        "portid": "22",
                        "state": {"state": "open"},
                        "scripts": [{"id": "banner", "output": "SSH-2.0-test"}],
                    },
                    {
                        "protocol": "tcp",
                        "portid": "443",
                        "state": {"state": "open"},
                        "scripts": [
                            {"id": "http-title", "output": "Welcome to nginx!"}
                        ],
                    },
                ],
            },
        }
        rules = [
            compile_tag_rule_definition(
                "nginx",
                "nginx",
                'http_title.bg:"welcome to nginx!"',
                ["vendor:nginx"],
            )
        ]
        ports = filtered_scans._matching_ports(  # pylint: disable=protected-access
            document,
            validate_search_query("tag:vendor:nginx"),
            rules,
            self.app.config,
        )
        self.assertEqual(ports, {443})

    def test_host_only_tag_does_not_invent_a_port(self):
        """A hostname tag can match a capture but cannot justify any TCP port."""
        document = self.document("host-only", 443)
        document["body"]["hostnames"] = [{"name": "example.org", "type": "user"}]
        rules = [
            compile_tag_rule_definition(
                "hostname", "hostname", "fqdn:example.org", ["source:hostname"]
            )
        ]
        ports = filtered_scans._matching_ports(  # pylint: disable=protected-access
            document,
            validate_search_query("tag:source:hostname"),
            rules,
            self.app.config,
        )
        self.assertFalse(ports)

    def test_requested_domain_matches_reported_open_ports(self):
        """A requested-domain filter can select its report's open ports."""
        document = self.document("fqdn", 443)
        document["body"]["hostnames"] = [{"name": "www.trollprod.org", "type": "user"}]
        ssh_port = self.document("fqdn", 22)["body"]["ports"][0]
        ssh_port["scripts"][0]["output"] = "SSH-2.0-test"
        document["body"]["ports"].append(ssh_port)
        requested = "domain_requested:trollprod.org"
        for query, expected in (
            (requested, {22, 443}),
            (f"{requested} AND banner.lk:hello", {443}),
        ):
            with self.subTest(query=query):
                # pylint: disable-next=protected-access
                ports = filtered_scans._matching_ports(
                    document, validate_search_query(query), [], self.app.config
                )
                self.assertEqual(ports, expected)

    def test_kvrocks_candidate_merge_is_idempotent(self):
        """Replaying one search page does not duplicate its target or ports."""
        target = self.db.session.query(Targets).one()
        store = FilteredWorkStore(self.redis, self.cycle_id, 1)
        store.begin(10, 20)
        work = [(target.id, "ip", "8.8.8.8", {443, 8443}, None)]
        store.add_candidates(work, 1, (19, 1))
        store.add_candidates(work, 2, (18, 1))
        store.finish_collection()
        self.assertEqual(
            store.groups(),
            [
                (
                    store.groups()[0][0],
                    {"kind": "ip", "family": None, "ports": "443,8443"},
                )
            ],
        )


class FilteredJobDeletionTest(ProfileApiFixture):
    """Exercise the Jobs list action with the production unique-cycle index."""

    def configure_catalogue(self):
        class JobsDeletionView(views.JobsView):
            route_base = "/jobsview"
            datamodel = SQLAInterface(Jobs)

        self.builder.add_view_no_menu(JobsDeletionView)

    def add_cycle(self, profile, target, started_at, status):
        finished = status == "finished"
        cycle = ScanProfileCycles(
            scanprofile=profile,
            started_at=started_at,
            finished_at=started_at + timedelta(minutes=5) if finished else None,
            status=status,
            filter_revision=1,
            preparation_status="queued",
        )
        job = Jobs(
            uid=str(uuid.uuid4()),
            scanprofile=profile,
            scanprofile_cycle=cycle,
            job=target.value,
            scan_ports="443",
            finished=finished,
        )
        job.targets.append(target)
        work = FilteredScanTargets(
            cycle=cycle,
            configured_target=target,
            target_kind="ip",
            target_value=target.value,
            ports="443",
            status="completed" if finished else "queued",
            completed_ports="443" if finished else None,
            job=job,
        )
        self.db.session.add(work)
        self.db.session.flush()
        return cycle, job, work

    def test_bulk_delete_requeues_only_the_latest_cycle_for_each_enabled_profile(self):
        self.enterContext(patch.object(views, "db", self.db))
        self.enterContext(patch.object(scan_cycles, "db", self.db))
        self.db.session.execute(
            text(
                "CREATE UNIQUE INDEX uq_scanprofile_cycles_one_running "
                "ON scanprofile_cycles(scanprofile_id) WHERE status = 'running'"
            )
        )
        target = Targets(value="192.0.2.10", is_ip_cidr=True)
        earlier = datetime(2026, 11, 24, 12)
        later = earlier + timedelta(hours=1)
        selected = []
        cases = []
        for status in ("running", "finished"):
            profile = ScanProfiles(
                name=status,
                search_query="banner.lk:hello",
                filter_enabled=True,
                filter_revision=1,
                apply_to_all=False,
            )
            old, old_job, old_work = self.add_cycle(
                profile, target, earlier, "finished"
            )
            recent, recent_job, recent_work = self.add_cycle(
                profile, target, later, status
            )
            if status == "running":
                profile.current_cycle_id = recent.id
            else:
                selected.append(recent_job.id)
            selected.append(old_job.id)
            cases.append((profile, old, old_work, recent, recent_work, status))
        self.db.session.commit()
        admin = self.builder.sm.find_user(username="Admin")
        with self.client.session_transaction() as session:
            session["_user_id"] = admin.get_id()

        data = {"action": "muldelete", "rowid": selected}
        response = self.client.post("/jobsview/action_post", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.db.session.query(Jobs).count(), 1)
        for profile, old, old_work, recent, recent_work, status in cases:
            with self.subTest(original_status=status):
                self.assertEqual(profile.current_cycle_id, recent.id)
                self.assertEqual(old.status, "finished")
                self.assertEqual(old.finished_at, earlier + timedelta(minutes=5))
                self.assertEqual(
                    (old_work.status, old_work.completed_ports), ("completed", "443")
                )
                self.assertIsNone(old_work.job_id)
                self.assertEqual(recent.status, "running")
                if status == "finished":
                    self.assertEqual(recent.preparation_status, "pending")
                    self.assertEqual(recent_work.status, "pending")
                    self.assertIsNone(recent_work.completed_ports)
                    self.assertIsNone(recent_work.job_id)
                else:
                    self.assertEqual(recent.preparation_status, "queued")
                    self.assertEqual(recent_work.status, "queued")
                    self.assertIsNotNone(recent_work.job_id)
        retry = self.client.post("/jobsview/action_post", data=data)
        self.assertEqual(retry.status_code, 302)


class FilteredScanMigrationTest(unittest.TestCase):
    """Ensure existing installations gain replay-safe filtered scan state."""

    def test_migration_is_idempotent(self):
        """Migration may be retried after an interrupted updater run."""
        migrate = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1]
                / "webapp"
                / "sql_upd"
                / "33_migrate_from_dc5447a7a2c8910615ae230137e7d9aa333ab09d.py"
            )
        )["migrate"]
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE scanprofiles (id INTEGER PRIMARY KEY);
            CREATE TABLE scanprofile_cycles (id INTEGER PRIMARY KEY);
            """)
        migrate(connection)
        migrate(connection)

        profile_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(scanprofiles)").fetchall()
        }
        cycle_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(scanprofile_cycles)"
            ).fetchall()
        }
        self.assertTrue(
            {"search_query", "filter_enabled", "filter_revision"}.issubset(
                profile_columns
            )
        )
        self.assertTrue(
            {
                "filter_revision",
                "preparation_status",
                "filter_query",
                "filter_from_ts",
                "filter_to_ts",
            }.issubset(cycle_columns)
        )
        self.assertIsNotNone(
            connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='filtered_scan_targets'"
            ).fetchone()
        )
        work_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(filtered_scan_targets)"
            ).fetchall()
        }
        self.assertIn("completed_ports", work_columns)

    def test_kvrocks_cutover_keeps_active_jobs_and_closes_old_cycle(self):
        """Migration drops queued preparation while active agents may report."""
        migrate = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1]
                / "webapp"
                / "sql_upd"
                / "36_migrate_from_dca246bd1bb5ebb51d51998595b860eab029798e.py"
            )
        )["migrate"]
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE scanprofiles (
                id INTEGER PRIMARY KEY,
                current_cycle_id INTEGER,
                last_cycle_finished_at DATETIME
            );
            CREATE TABLE scanprofile_cycles (
                id INTEGER PRIMARY KEY,
                scanprofile_id INTEGER,
                status TEXT,
                finished_at DATETIME,
                filter_revision INTEGER,
                preparation_status TEXT
            );
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY,
                scanprofile_cycle_id INTEGER,
                active BOOLEAN,
                finished BOOLEAN,
                exported BOOLEAN,
                job_end DATETIME
            );
            CREATE TABLE filtered_scan_targets (
                id INTEGER PRIMARY KEY,
                cycle_id INTEGER
            );
            INSERT INTO scanprofiles VALUES (1, 10, NULL);
            INSERT INTO scanprofile_cycles VALUES (10, 1, 'running', NULL, 7, 'ready');
            INSERT INTO jobs VALUES (20, 10, 0, 0, 0, NULL);
            INSERT INTO jobs VALUES (21, 10, 1, 0, 0, NULL);
            INSERT INTO filtered_scan_targets VALUES (30, 10);
        """)
        migrate(connection)
        migrate(connection)
        self.assertEqual(
            connection.execute(
                "SELECT active, finished, exported FROM jobs ORDER BY id"
            ).fetchall(),
            [(0, 1, 1), (1, 0, 0)],
        )
        self.assertEqual(
            connection.execute(
                "SELECT status, preparation_status FROM scanprofile_cycles"
            ).fetchone(),
            ("finished", "legacy_sql_superseded"),
        )
        self.assertIsNone(
            connection.execute("SELECT current_cycle_id FROM scanprofiles").fetchone()[
                0
            ]
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM filtered_scan_targets").fetchone()[
                0
            ],
            0,
        )


if __name__ == "__main__":
    unittest.main()
