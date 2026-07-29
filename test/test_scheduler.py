#!/usr/bin/env python3
"""Regression tests for scheduler job recovery."""

# pylint: disable=wrong-import-position

import importlib
import os
import sys
from datetime import datetime, timedelta
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
