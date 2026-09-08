#!/usr/bin/env python3
"""Regression tests for scheduler job recovery."""

# pylint: disable=wrong-import-position,protected-access,duplicate-code,too-many-public-methods

import importlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import TestCase, mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))


class StalledJobWatchdogTest(TestCase):
    """Tests for the scheduler's two-hour stalled-job watchdog."""

    @classmethod
    def setUpClass(cls):
        """Import scheduler with external services mocked."""
        with mock.patch("meilisearch.Client") as client, mock.patch(
            "app.utils.kvrocks.KVrocksIndexer"
        ) as kvrocks_indexer:
            client.return_value.index.return_value.get_searchable_attributes.return_value = (
                []
            )
            cls.scheduler = importlib.import_module("app.scheduler")
            cls.meili_client_constructor = client
            cls.kvrocks_indexer_constructor = kvrocks_indexer

    def _export_context(self, meili_index, kvrocks_index):
        """Build isolated export dependencies for state-machine tests."""
        return self.scheduler.ExportContext(
            meili_idx=meili_index,
            kvrocks_idx=kvrocks_index,
            input_dir="/tmp",
            parser_config={},
            active_tag_rules=[],
        )

    def test_timeout_is_exactly_two_hours(self):
        """A job at the two-hour boundary is eligible for release."""
        now = datetime(2026, 7, 29, 12, 0, 0)
        self.assertEqual(
            now - self.scheduler.STALLED_JOB_TIMEOUT,
            datetime(2026, 7, 29, 10, 0, 0),
        )

    def test_watchdog_updates_only_stalled_job_state(self):
        """Watchdog clears claim fields and preserves unfinished state."""
        session = mock.Mock()
        query = session.query.return_value
        query.filter.return_value.update.return_value = 2
        with mock.patch.object(self.scheduler.db, "session", session):
            summary = self.scheduler.task_release_stalled_jobs(
                datetime(2026, 7, 29, 12, 0, 0)
            )

        self.assertEqual(summary, {"stalled_jobs_released": 2})
        session.commit.assert_called_once_with()
        updates = query.filter.return_value.update.call_args.args[0]
        self.assertFalse(updates[self.scheduler.Jobs.active])
        self.assertIsNone(updates[self.scheduler.Jobs.bot_id])
        self.assertIsNone(updates[self.scheduler.Jobs.job_start])

    def test_watchdog_does_not_commit_when_no_job_matches(self):
        """No-op watchdog tick does not create an unnecessary transaction."""
        session = mock.Mock()
        session.query.return_value.filter.return_value.update.return_value = 0
        with mock.patch.object(self.scheduler.db, "session", session):
            summary = self.scheduler.task_release_stalled_jobs()

        self.assertEqual(summary, {"stalled_jobs_released": 0})
        session.commit.assert_not_called()

    def test_timeout_is_timedelta(self):
        """Timeout remains a fixed two-hour duration, not scheduler interval."""
        self.assertEqual(self.scheduler.STALLED_JOB_TIMEOUT, timedelta(hours=2))

    def test_backend_clients_have_finite_request_timeouts(self):
        """An unavailable search backend cannot occupy the scheduler forever."""
        self.assertEqual(
            self.meili_client_constructor.call_args.kwargs["timeout"],
            10,
        )
        self.assertEqual(
            self.kvrocks_indexer_constructor.call_args.kwargs["socket_timeout"],
            10,
        )

    def test_backend_maintenance_has_an_independent_scheduler_slot(self):
        """A stuck maintenance run cannot suppress scan orchestration ticks."""
        jobs = {job.id: job for job in self.scheduler.scheduler.get_jobs()}

        self.assertIn("scan_orchestration", jobs)
        self.assertIn("scheduler_maintenance", jobs)
        self.assertIs(
            jobs["scan_orchestration"].func,
            self.scheduler.task_master_of_puppets,
        )
        self.assertIs(
            jobs["scheduler_maintenance"].func,
            self.scheduler.task_scheduler_maintenance,
        )

    def test_scan_tick_generates_jobs_without_entering_backend_maintenance(self):
        """The scan tick cannot call a slow export path before creating jobs."""
        call_order = []

        with mock.patch.object(
            self.scheduler,
            "task_release_stalled_jobs",
            side_effect=lambda: call_order.append("watchdog") or {},
        ), mock.patch.object(
            self.scheduler,
            "task_create_jobs",
            side_effect=lambda: call_order.append("create_jobs") or {"jobs_created": 1},
        ), mock.patch.object(
            self.scheduler,
            "task_sync_queued_profile_jobs",
            side_effect=lambda: call_order.append("profile_sync") or {},
        ), mock.patch.object(
            self.scheduler,
            "task_export_to_dbs",
            side_effect=AssertionError("scan tick entered backend export"),
        ):
            self.scheduler.task_master_of_puppets()

        self.assertEqual(call_order, ["watchdog", "create_jobs", "profile_sync"])

    def test_due_state_query_applies_cycle_target_boundary(self):
        """Targets above current cycle high-water mark remain for next cycle."""
        session = mock.Mock()
        session.execute.return_value.fetchall.return_value = []
        profile = SimpleNamespace(
            id=7,
            scan_cycle_minutes=60,
            apply_to_all=True,
        )

        with mock.patch.object(self.scheduler.db, "session", session):
            states = self.scheduler._load_due_states_for_profile(
                profile,
                datetime(2026, 8, 20, 12, 0, 0),
                state_limit=256,
                max_target_id=123,
            )

        self.assertEqual(states, [])
        sql_clause, params = session.execute.call_args.args
        self.assertIn("t.id <= :max_target_id", str(sql_clause))
        self.assertEqual(params["max_target_id"], 123)

    def test_large_ipv4_target_is_split_directly_into_atomic_24_jobs(self):
        """A /16 becomes 256 /24 jobs without losing part of the target."""
        target = SimpleNamespace(id=1, value="8.8.0.0/16")
        state = SimpleNamespace(id=1, target=target)

        range_chunks, small_ranges, hostname_records = (
            self.scheduler._classify_due_states_for_chunks(
                [state],
                max_large_range_jobs=1,
            )
        )

        self.assertEqual(len(range_chunks), 256)
        self.assertEqual(range_chunks[0]["cidrs"], ["8.8.0.0/24"])
        self.assertEqual(range_chunks[-1]["cidrs"], ["8.8.255.0/24"])
        self.assertEqual(small_ranges, [])
        self.assertEqual(hostname_records, [])

    def test_large_ipv4_target_queues_all_256_jobs_as_one_atomic_target(self):
        """The soft one-job limit cannot leave a /16 only partly scheduled."""

        class FakeJob:  # pylint: disable=too-few-public-methods
            """Minimal job object used to inspect scheduler staging."""

            def __init__(self):
                self.targets = []

        profile = SimpleNamespace(
            id=7,
            name="profile",
            priority=2,
            nmap_additional_params="-4",
        )
        target = SimpleNamespace(id=1, value="8.8.0.0/16", working=False)
        state = SimpleNamespace(id=1, target=target, working=False)
        session = mock.Mock()

        with mock.patch.object(self.scheduler, "Jobs", FakeJob), mock.patch.object(
            self.scheduler.db, "session", session
        ):
            summary = self.scheduler._stage_jobs_for_profile(
                profile,
                [state],
                "80",
                "",
                SimpleNamespace(id=3),
                max_jobs=1,
            )

        queued_jobs = [call.args[0] for call in session.add.call_args_list]
        self.assertEqual(summary["range_jobs"], 256)
        self.assertEqual(len(queued_jobs), 256)
        self.assertEqual(queued_jobs[0].job, "8.8.0.0/24")
        self.assertEqual(queued_jobs[-1].job, "8.8.255.0/24")
        self.assertTrue(target.working)
        self.assertTrue(state.working)

    def test_fqdn_transaction_builds_one_full_256_host_job(self):
        """One bounded transaction yields one complete FQDN job."""
        hostname_records = []
        for index in range(self.scheduler.DEFAULT_QUEUE_STATE_BATCH_SIZE):
            hostname_records.append(
                {
                    "hosts": [f"host-{index}.example"],
                    "targets": [SimpleNamespace(id=index)],
                    "states": [SimpleNamespace(id=index)],
                }
            )
        hostname_chunks = []

        added = self.scheduler._merge_hostnames_into_chunks(
            hostname_records,
            hostname_chunks,
            max_chunks=1,
        )

        self.assertEqual(added, 1)
        self.assertEqual(len(hostname_chunks), 1)
        self.assertEqual(
            len(hostname_chunks[0]["hosts"]),
            self.scheduler.JOB_TARGET_CHUNK_SIZE,
        )

    def test_state_sync_commits_even_when_every_state_already_exists(self):
        """A no-op state search never starts a SQLite write transaction."""
        session = mock.Mock()
        session.execute.return_value.fetchall.return_value = []
        session.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
            []
        )

        with mock.patch.object(self.scheduler.db, "session", session):
            inserted = self.scheduler._sync_missing_scan_states()

        self.assertEqual(inserted, 0)
        self.assertEqual(session.commit.call_count, 2)
        executed_sql = [str(call.args[0]) for call in session.execute.call_args_list]
        self.assertTrue(executed_sql)
        self.assertTrue(all("INSERT" not in sql.upper() for sql in executed_sql))

    def test_state_sync_closes_read_before_bounded_insert(self):
        """Missing-state discovery cannot retain a snapshot into its write."""
        session = mock.Mock()
        select_result = mock.Mock()
        select_result.fetchall.return_value = [(10, 7)]
        insert_result = mock.Mock(rowcount=1)
        events = []

        def execute(statement, _params):
            operation = str(statement).strip().split(None, 1)[0].upper()
            events.append(operation)
            return select_result if operation == "SELECT" else insert_result

        session.execute.side_effect = execute
        session.commit.side_effect = lambda: events.append("COMMIT")
        session.query.return_value.filter.return_value.order_by.return_value.all.return_value = (
            []
        )

        with mock.patch.object(self.scheduler.db, "session", session):
            inserted = self.scheduler._sync_missing_scan_states()

        self.assertEqual(inserted, 1)
        self.assertEqual(events[:4], ["SELECT", "COMMIT", "INSERT", "COMMIT"])

    def test_profile_rotation_follows_query_order_instead_of_numeric_id(self):
        """Time-bounded ticks resume after the prior priority-ordered profile."""
        profiles = [
            SimpleNamespace(id=9),
            SimpleNamespace(id=1),
            SimpleNamespace(id=2),
        ]
        previous_cursor = self.scheduler.db.app.config.get(
            "scheduler_profile_cursor_id"
        )
        self.scheduler.db.app.config["scheduler_profile_cursor_id"] = 9
        try:
            rotated = self.scheduler._rotate_profiles_for_tick(profiles)
        finally:
            self.scheduler.db.app.config["scheduler_profile_cursor_id"] = (
                previous_cursor
            )

        self.assertEqual([profile.id for profile in rotated], [1, 2, 9])

    def test_queue_generation_yields_after_one_committed_profile_batch(self):
        """An expired time budget preserves completed work and defers the rest."""
        profiles = [
            SimpleNamespace(
                id=9,
                name="high",
                priority=3,
                scan_cycle_minutes=60,
                apply_to_all=True,
                nmap_additional_params=None,
            ),
            SimpleNamespace(
                id=1,
                name="normal",
                priority=2,
                scan_cycle_minutes=60,
                apply_to_all=True,
                nmap_additional_params=None,
            ),
        ]
        cycle = SimpleNamespace(max_target_id=100, status="running")
        session = mock.MagicMock()
        session.query.return_value.order_by.return_value.all.return_value = profiles
        config_values = {
            "SCHEDULER_QUEUE_TARGET_JOBS_PER_PROFILE": 256,
            "SCHEDULER_QUEUE_STATE_BATCH_SIZE": 4096,
            "SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK": 1024,
            "SCHEDULER_QUEUE_TIME_BUDGET_SECONDS": 45,
        }
        previous_cursor = self.scheduler.db.app.config.get(
            "scheduler_profile_cursor_id"
        )
        self.scheduler.db.app.config["scheduler_profile_cursor_id"] = 0
        try:
            with mock.patch.object(
                self.scheduler.db, "session", session
            ), mock.patch.object(
                self.scheduler, "_should_run_orphan_state_release", return_value=False
            ), mock.patch.object(
                self.scheduler, "_sync_missing_scan_states", return_value=0
            ), mock.patch.object(
                self.scheduler,
                "_get_scheduler_int_config",
                side_effect=lambda name, _default, minimum=1: max(
                    config_values[name], minimum
                ),
            ), mock.patch.object(
                self.scheduler, "_get_waiting_job_counts_by_profile", return_value={}
            ), mock.patch.object(
                self.scheduler, "_serialize_profile_ports", return_value="80"
            ), mock.patch.object(
                self.scheduler, "_serialize_profile_nses", return_value=""
            ), mock.patch.object(
                self.scheduler, "get_running_scanprofile_cycle", return_value=cycle
            ), mock.patch.object(
                self.scheduler, "reconcile_scanprofile_cycle", return_value=cycle
            ), mock.patch.object(
                self.scheduler,
                "_load_due_states_for_profile",
                return_value=[SimpleNamespace(id=1)],
            ), mock.patch.object(
                self.scheduler, "get_or_create_running_cycle", return_value=cycle
            ), mock.patch.object(
                self.scheduler,
                "_stage_jobs_for_profile",
                return_value={
                    "scheduled_states": 256,
                    "range_jobs": 1,
                    "host_jobs": 0,
                },
            ) as stage_jobs, mock.patch.object(
                self.scheduler,
                "_queue_time_budget_reached",
                side_effect=lambda _deadline, jobs_created: jobs_created > 0,
            ):
                summary = self.scheduler.task_create_jobs()
        finally:
            self.scheduler.db.app.config["scheduler_profile_cursor_id"] = (
                previous_cursor
            )

        self.assertEqual(summary["jobs_created"], 1)
        self.assertTrue(summary["time_budget_exhausted"])
        stage_jobs.assert_called_once()
        self.assertEqual(session.commit.call_count, 2)

    def test_queue_generation_commits_every_256_state_batch(self):
        """Result writers get a transaction boundary between queue batches."""
        profile = SimpleNamespace(
            id=9,
            name="high",
            priority=3,
            scan_cycle_minutes=60,
            apply_to_all=True,
            nmap_additional_params=None,
        )
        cycle = SimpleNamespace(max_target_id=100, status="running")
        session = mock.MagicMock()
        session.query.return_value.order_by.return_value.all.return_value = [profile]
        config_values = {
            "SCHEDULER_QUEUE_TARGET_JOBS_PER_PROFILE": 2,
            # Simulate a stale production value from the earlier implementation.
            "SCHEDULER_QUEUE_STATE_BATCH_SIZE": 4096,
            "SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK": 10,
            "SCHEDULER_QUEUE_TIME_BUDGET_SECONDS": 45,
        }
        previous_cursor = self.scheduler.db.app.config.get(
            "scheduler_profile_cursor_id"
        )
        self.scheduler.db.app.config["scheduler_profile_cursor_id"] = 0
        try:
            with mock.patch.object(
                self.scheduler.db, "session", session
            ), mock.patch.object(
                self.scheduler, "_should_run_orphan_state_release", return_value=False
            ), mock.patch.object(
                self.scheduler, "_sync_missing_scan_states", return_value=0
            ), mock.patch.object(
                self.scheduler,
                "_get_scheduler_int_config",
                side_effect=lambda name, _default, minimum=1: max(
                    config_values[name], minimum
                ),
            ), mock.patch.object(
                self.scheduler, "_get_waiting_job_counts_by_profile", return_value={}
            ), mock.patch.object(
                self.scheduler, "_serialize_profile_ports", return_value="80"
            ), mock.patch.object(
                self.scheduler, "_serialize_profile_nses", return_value=""
            ), mock.patch.object(
                self.scheduler, "get_running_scanprofile_cycle", return_value=cycle
            ), mock.patch.object(
                self.scheduler, "reconcile_scanprofile_cycle", return_value=cycle
            ), mock.patch.object(
                self.scheduler,
                "_load_due_states_for_profile",
                return_value=[SimpleNamespace(id=1)],
            ) as load_states, mock.patch.object(
                self.scheduler,
                "_stage_jobs_for_profile",
                return_value={
                    "scheduled_states": 256,
                    "range_jobs": 0,
                    "host_jobs": 1,
                },
            ) as stage_jobs, mock.patch.object(
                self.scheduler,
                "_queue_time_budget_reached",
                return_value=False,
            ):
                summary = self.scheduler.task_create_jobs()
        finally:
            self.scheduler.db.app.config["scheduler_profile_cursor_id"] = (
                previous_cursor
            )

        self.assertEqual(summary["jobs_created"], 2)
        self.assertEqual(stage_jobs.call_count, 2)
        self.assertEqual(session.commit.call_count, 3)
        self.assertEqual(
            [call.args[2] for call in load_states.call_args_list],
            [self.scheduler.JOB_TARGET_CHUNK_SIZE] * 2,
        )
        self.assertEqual(
            [call.kwargs["max_jobs"] for call in stage_jobs.call_args_list],
            [2, 1],
        )
        self.assertEqual(session.no_autoflush.__enter__.call_count, 3)

    def test_persisted_pending_task_never_writes_kvrocks(self):
        """Queued task remains attached to job without Kvrocks mutation."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.get_task.return_value = SimpleNamespace(
            status="enqueued",
            error=None,
        )
        job_state = {
            "id": 1,
            "uid": "job-one",
            "exported": False,
            "task_uid": 42,
            "submitted": 1,
            "total": 1,
        }

        result = self.scheduler._process_persisted_meili_task(
            self._export_context(meili_index, kvrocks_index),
            42,
            [job_state],
        )

        self.assertEqual(result["status"], "enqueued")
        self.assertEqual(job_state["task_uid"], 42)
        self.assertFalse(job_state["exported"])
        meili_index.add_documents.assert_not_called()
        kvrocks_index.add_documents_batch.assert_not_called()

    def test_new_task_is_persisted_without_polling_or_kvrocks(self):
        """Submission yields immediately so export cannot occupy the scheduler."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.add_documents.return_value = SimpleNamespace(task_uid=45)
        job_state = {
            "id": 1,
            "uid": "job-one",
            "exported": False,
            "task_uid": None,
            "submitted": 1,
            "total": 1,
        }
        batch_state = {
            "documents": [{"id": "one"}],
            "jobs": [job_state],
            "ready_documents": 0,
            "ready_jobs": 0,
        }
        persisted_task_uids = []

        def persist(states):
            persisted_task_uids.append(states[0]["task_uid"])

        with mock.patch.object(
            self.scheduler,
            "_persist_meili_export_states",
            side_effect=persist,
        ):
            summary = self.scheduler._submit_meili_export_batch(
                self._export_context(meili_index, kvrocks_index),
                1,
                batch_state,
            )

        self.assertEqual(persisted_task_uids, [45])
        self.assertEqual(job_state["task_uid"], 45)
        self.assertEqual(summary["meili_tasks_pending"], 1)
        meili_index.get_task.assert_not_called()
        kvrocks_index.add_documents_batch.assert_not_called()

    def test_succeeded_persisted_task_writes_kvrocks_after_status(self):
        """Confirmed Meili success precedes Kvrocks and job completion."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        calls = []
        meili_index.get_task.side_effect = lambda *args, **kwargs: (
            calls.append("meili") or SimpleNamespace(status="succeeded", error=None)
        )
        kvrocks_index.add_documents_batch.side_effect = lambda _docs: calls.append(
            "kvrocks"
        )
        job_state = {
            "id": 1,
            "uid": "job-one",
            "exported": False,
            "task_uid": 42,
            "submitted": 1,
            "total": 1,
        }
        with mock.patch.object(
            self.scheduler,
            "_load_job_export_documents",
            side_effect=lambda *_args: (
                calls.append("load") or ([{"id": "one"}], [{"uid": "one"}])
            ),
        ):
            result = self.scheduler._process_persisted_meili_task(
                self._export_context(meili_index, kvrocks_index),
                42,
                [job_state],
            )

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["documents_exported"], 1)
        self.assertEqual(calls, ["meili", "load", "kvrocks"])
        self.assertTrue(job_state["exported"])
        self.assertIsNone(job_state["task_uid"])
        self.assertEqual(job_state["submitted"], 0)
        meili_index.get_task.assert_called_once_with(42)

    def test_partial_job_waits_for_all_meili_batches_before_kvrocks(self):
        """One successful chunk cannot expose incomplete job in Kvrocks."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.get_task.return_value = SimpleNamespace(
            status="succeeded",
            error=None,
        )
        job_state = {
            "id": 1,
            "uid": "large-job",
            "exported": False,
            "task_uid": 46,
            "submitted": 2500,
            "total": 3000,
        }

        result = self.scheduler._process_persisted_meili_task(
            self._export_context(meili_index, kvrocks_index),
            46,
            [job_state],
        )

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["documents_exported"], 0)
        self.assertIsNone(job_state["task_uid"])
        self.assertEqual(job_state["submitted"], 2500)
        self.assertFalse(job_state["exported"])
        kvrocks_index.add_documents_batch.assert_not_called()

    def test_failed_meili_export_never_writes_kvrocks(self):
        """Rejected task resets durable state and leaves Kvrocks untouched."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.get_task.return_value = SimpleNamespace(
            status="failed",
            error={"message": "bad document"},
        )
        job_state = {
            "id": 1,
            "uid": "job-one",
            "exported": False,
            "task_uid": 43,
            "submitted": 1,
            "total": 1,
        }

        result = self.scheduler._process_persisted_meili_task(
            self._export_context(meili_index, kvrocks_index),
            43,
            [job_state],
        )

        self.assertEqual(result["status"], "failed")
        self.assertIsNone(job_state["task_uid"])
        self.assertEqual(job_state["submitted"], 0)
        self.assertIsNone(job_state["total"])
        kvrocks_index.add_documents_batch.assert_not_called()


class MeiliExportStateMigrationTest(TestCase):
    """Validate durable scheduler state migration for existing jobs."""

    @classmethod
    def setUpClass(cls):
        migration_path = (
            Path(__file__).resolve().parents[1]
            / "webapp"
            / "sql_upd"
            / "21_migrate_from_c1ef29af4ac597787b67d99982f9baade1817222.py"
        )
        spec = importlib.util.spec_from_file_location(
            "meili_export_state_migration",
            migration_path,
        )
        cls.migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.migration)

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.cursor = self.connection.cursor()
        self.cursor.executescript("""
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY,
                uid VARCHAR(36) NOT NULL,
                exported BOOLEAN NOT NULL DEFAULT 0
            );
            INSERT INTO jobs (id, uid, exported) VALUES (1, 'job-one', 0);
            """)

    def tearDown(self):
        self.connection.close()

    def test_migration_adds_idempotent_pending_task_state(self):
        """Existing jobs start with no task and zero submitted documents."""
        self.migration.migrate(self.cursor)
        self.migration.migrate(self.cursor)

        columns = {
            row[1] for row in self.cursor.execute("PRAGMA table_info(jobs)").fetchall()
        }
        state = self.cursor.execute(
            "SELECT meili_task_uid, meili_documents_submitted, "
            "meili_documents_total FROM jobs WHERE id = 1"
        ).fetchone()
        self.assertTrue(
            {
                "meili_task_uid",
                "meili_documents_submitted",
                "meili_documents_total",
            }.issubset(columns)
        )
        self.assertEqual(state, (None, 0, None))
