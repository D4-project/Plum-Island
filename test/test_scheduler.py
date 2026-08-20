#!/usr/bin/env python3
"""Regression tests for scheduler job recovery."""

# pylint: disable=wrong-import-position,protected-access,duplicate-code

import importlib
import os
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
        ):
            client.return_value.index.return_value.get_searchable_attributes.return_value = (
                []
            )
            cls.scheduler = importlib.import_module("app.scheduler")

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

    def test_export_batch_waits_for_meili_before_kvrocks(self):
        """Kvrocks is written only after Meilisearch confirms success."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.add_documents.return_value = SimpleNamespace(task_uid=42)
        meili_index.wait_for_task.return_value = SimpleNamespace(
            status="succeeded",
            error=None,
        )
        calls = []
        meili_index.wait_for_task.side_effect = lambda *args, **kwargs: (
            calls.append("meili") or SimpleNamespace(status="succeeded", error=None)
        )
        kvrocks_index.add_documents_batch.side_effect = lambda _docs: calls.append(
            "kvrocks"
        )

        exported = self.scheduler._export_document_batch(
            meili_index,
            kvrocks_index,
            [{"id": "one"}],
            [{"uid": "one"}],
            timeout_ms=1234,
        )

        self.assertEqual(exported, 1)
        self.assertEqual(calls, ["meili", "kvrocks"])
        meili_index.wait_for_task.assert_called_once_with(
            42,
            timeout_in_ms=1234,
        )

    def test_failed_meili_export_never_writes_kvrocks(self):
        """Rejected Meilisearch tasks leave Kvrocks untouched for retry."""
        meili_index = mock.Mock()
        kvrocks_index = mock.Mock()
        meili_index.add_documents.return_value = SimpleNamespace(task_uid=43)
        meili_index.wait_for_task.return_value = SimpleNamespace(
            status="failed",
            error={"message": "bad document"},
        )

        with self.assertRaisesRegex(
            self.scheduler.MeiliExportTaskError,
            "task 43 ended with status failed",
        ):
            self.scheduler._export_document_batch(
                meili_index,
                kvrocks_index,
                [{"id": "one"}],
                [{"uid": "one"}],
            )

        kvrocks_index.add_documents_batch.assert_not_called()
