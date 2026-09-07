#!/usr/bin/env python3
"""Regression tests for scheduler job recovery."""

# pylint: disable=wrong-import-position,protected-access,duplicate-code

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
