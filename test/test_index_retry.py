"""Backend outages back off without losing checkpoints or masking data errors."""

import os
import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch

import redis
from app.utils.index_generations import ACTIVE, CONTROL
from app.utils.index_pacing import PacedReconciliationWorker
from app.utils.index_reconciliation import ReconciliationWorker, SnapshotInvalid
from app.utils.index_retry import retry_delay, transient_error
from app.utils.index_supervisor import IndexSupervisor
from meilisearch.errors import MeilisearchApiError, MeilisearchCommunicationError
from requests import Response


class RetryPolicyTest(unittest.TestCase):
    """Regression checks for retry policy test."""

    def api_error(self, status):
        """Provide the api error test fixture."""
        response = Response()
        response.status_code = status
        response._content = b""
        return MeilisearchApiError("backend response", response)

    def test_only_transient_errors_are_retried(self):
        """Verify only transient errors are retried."""
        for error in (
            redis.exceptions.TimeoutError(),
            redis.exceptions.ConnectionError(),
            redis.exceptions.BusyLoadingError(),
            MeilisearchCommunicationError("offline"),
            self.api_error(429),
            self.api_error(503),
        ):
            self.assertTrue(transient_error(error), type(error))
        for error in (
            ValueError("bad JSON"),
            SnapshotInvalid("parser changed"),
            redis.exceptions.AuthenticationError(),
            redis.exceptions.ResponseError("WRONGTYPE"),
            self.api_error(401),
            self.api_error(404),
        ):
            self.assertFalse(transient_error(error), type(error))

    def test_reporting_outage_does_not_hide_original_data_error(self):
        """Verify reporting outage does not hide original data error."""
        error = redis.exceptions.TimeoutError("status write timed out")
        error.__context__ = ValueError("invalid source JSON")
        self.assertFalse(transient_error(error))

    def test_delay_grows_and_is_capped(self):
        """Verify delay grows and is capped."""
        with patch("app.utils.index_retry.random.uniform", return_value=1):
            self.assertEqual(
                [retry_delay(n) for n in (1, 2, 3, 4, 5, 100)],
                [30, 60, 120, 240, 300, 300],
            )


class SupervisorRetryTest(unittest.TestCase):
    """Regression checks for supervisor retry test."""

    def setUp(self):
        """Create isolated state for the regression checks."""
        with patch("app.utils.index_supervisor.publish_controller_settings"):
            self.supervisor = IndexSupervisor(Mock(), {})

    def test_tick_defers_and_recovers_without_sleeping(self):
        """Verify tick defers and recovers without sleeping."""
        clock = [0.0]
        with patch(
            "app.utils.index_supervisor.time.monotonic", side_effect=lambda: clock[0]
        ), patch(
            "app.utils.index_supervisor.retry_delay", return_value=30
        ), patch.object(
            self.supervisor,
            "_tick",
            side_effect=[redis.exceptions.TimeoutError(), None],
        ) as tick, patch(
            "app.utils.index_supervisor.time.sleep"
        ) as sleep:
            self.supervisor.tick({})
            self.assertEqual(self.supervisor.retry_at, 30)
            clock[0] = 29
            self.supervisor.tick({})
            self.assertEqual(tick.call_count, 1)
            clock[0] = 30
            self.supervisor.tick({})
            self.assertEqual(tick.call_count, 2)
            self.assertEqual(self.supervisor.retry_attempts, 0)
            sleep.assert_not_called()

    def test_permanent_errors_are_not_suppressed(self):
        """Verify permanent errors are not suppressed."""
        with patch.object(
            self.supervisor, "_tick", side_effect=ValueError("invalid snapshot")
        ):
            with self.assertRaises(ValueError):
                self.supervisor.tick({})

    def test_snapshot_connection_failure_is_deferred_without_spawning(self):
        """Verify snapshot connection failure is deferred without spawning."""
        with patch(
            "app.utils.index_supervisor.queue_snapshot",
            side_effect=redis.exceptions.TimeoutError(),
        ), patch("app.utils.index_supervisor.subprocess.Popen") as spawn:
            self.supervisor.tick({"revision": "committed-in-sql"})
            self.assertEqual(self.supervisor.retry_attempts, 1)
            spawn.assert_not_called()

    def test_stop_and_disable_still_work_during_cooldown(self):
        """Verify stop and disable still work during cooldown."""
        self.supervisor.process = Mock()
        self.supervisor.process.poll.return_value = None
        self.supervisor.retry_at = float("inf")
        self.supervisor.config["TAG_RECONCILIATION_ENABLED"] = False
        self.supervisor.tick({})
        self.supervisor.process.terminate.assert_called_once()
        self.supervisor.stop()
        self.assertTrue(self.supervisor.stopped)


class WorkerRetryTest(unittest.TestCase):
    """Regression checks for worker retry test."""

    def setUp(self):
        """Create isolated state for the regression checks."""
        self.raw = Mock()
        self.worker = PacedReconciliationWorker(self.raw, Mock(), {})

    def test_worker_reloads_durable_state_after_timeout(self):
        """Verify worker reloads durable state after timeout."""
        self.worker.job = {
            "id": "staging",
            "snapshot": {"revision": "frozen"},
            "pending_uids": ["one"],
        }
        self.worker._inputs_saved = True
        with patch.object(
            ReconciliationWorker,
            "run",
            side_effect=[redis.exceptions.TimeoutError(), None],
        ) as run, patch.object(
            self.worker, "_record_backend_retry", return_value=False
        ), patch.object(
            self.worker, "_wait_backend_retry", return_value=True
        ) as wait:
            self.worker.run()
            self.assertEqual(run.call_count, 2)
            wait.assert_called_once()
            self.assertIsNone(self.worker.job)
            self.assertFalse(self.worker._inputs_saved)

    def test_status_failure_is_best_effort(self):
        """Verify status failure is best effort."""
        self.worker.job = {"id": "staging"}
        self.raw.get.side_effect = redis.exceptions.TimeoutError()
        with patch.object(self.worker, "checkpoint") as checkpoint:
            self.assertFalse(self.worker._record_backend_retry(30))
            checkpoint.assert_not_called()

    def test_lost_publication_reply_never_overwrites_success(self):
        """Verify lost publication reply never overwrites success."""
        self.worker.job = {"id": "staging", "phase": "done"}
        self.raw.get.return_value = "staging"
        with patch.object(
            ReconciliationWorker, "run", side_effect=redis.exceptions.TimeoutError()
        ), patch.object(self.worker, "checkpoint") as checkpoint, patch.object(
            self.worker, "_wait_backend_retry"
        ) as wait:
            self.worker.run()
            self.raw.get.assert_called_with(ACTIVE)
            checkpoint.assert_not_called()
            wait.assert_not_called()

    def test_retry_status_is_explicit(self):
        """Verify retry status is explicit."""
        self.worker.job = {"id": "staging"}
        self.raw.get.return_value = "active"
        with patch.object(self.worker, "checkpoint") as checkpoint:
            self.assertFalse(self.worker._record_backend_retry(30))
            self.assertEqual(checkpoint.call_args.kwargs["phase"], "retrying")
            self.raw.delete.assert_called_with(CONTROL + "failure")

    def test_stopping_during_backoff_records_pause_when_backend_recovers(self):
        """Verify stopping during backoff records pause when backend recovers."""
        self.worker.job = {"id": "staging"}
        self.raw.get.return_value = "active"
        with patch.object(self.worker, "checkpoint") as checkpoint:
            self.worker._record_backend_pause()
            self.assertEqual(checkpoint.call_args.kwargs["phase"], "paused")
            self.assertEqual(checkpoint.call_args.kwargs["retry_at"], 0)

    def test_permanent_error_remains_visible(self):
        """Verify permanent error remains visible."""
        with patch.object(
            ReconciliationWorker, "run", side_effect=SnapshotInvalid("changed")
        ), patch.object(self.worker, "_wait_backend_retry") as wait:
            with self.assertRaises(SnapshotInvalid):
                self.worker.run()
            wait.assert_not_called()

    def test_stop_interrupts_backoff(self):
        """Verify stop interrupts backoff."""

        def stop(_seconds):
            """Provide the stop test fixture."""
            self.worker.stopping = True

        with patch("app.utils.index_pacing.time.sleep", side_effect=stop) as sleep:
            self.assertFalse(self.worker._wait_backend_retry(300))
            sleep.assert_called_once()
            self.assertLessEqual(sleep.call_args.args[0], 0.5)

    def test_parent_exit_interrupts_backoff(self):
        """Verify parent exit interrupts backoff."""
        with patch.dict(os.environ, PLUM_INDEX_PARENT_PID="123"), patch(
            "app.utils.index_pacing.os.getppid", return_value=456
        ), patch("app.utils.index_pacing.time.sleep") as sleep:
            self.assertFalse(self.worker._wait_backend_retry(300))
            self.assertTrue(self.worker.stopping)
            sleep.assert_not_called()

    def test_checkpoint_outage_cannot_prevent_resuming_same_unit(self):
        """Verify checkpoint outage cannot prevent resuming same unit."""
        durable = {
            "id": "staging",
            "snapshot": {"revision": "frozen"},
            "attempts": 0,
            "candidates_ready": True,
            "pending_uids": ["one"],
            "scan_complete": False,
        }
        starts = []

        def start():
            """Provide the start test fixture."""
            self.worker.job = dict(durable)
            starts.append(self.worker.job["pending_uids"][:])
            return True

        units = []

        def scan():
            """Provide the scan test fixture."""
            units.append(self.worker.job["pending_uids"][:])
            if len(units) == 1:
                raise redis.exceptions.TimeoutError("write response lost")
            self.worker.stopping = True

        self.raw.get.side_effect = redis.exceptions.TimeoutError(
            "backend still unavailable"
        )
        with patch(
            "app.utils.index_reconciliation.file_lock", return_value=nullcontext()
        ), patch.object(self.worker, "start", side_effect=start), patch.object(
            self.worker, "scan_batch", side_effect=scan
        ), patch.object(
            self.worker, "checkpoint"
        ), patch.object(
            self.worker, "_wait_backend_retry", return_value=True
        ):
            self.worker.run()
        self.assertEqual(starts, [["one"], ["one"]])
        self.assertEqual(units, [["one"], ["one"]])
        self.assertEqual(durable["snapshot"], {"revision": "frozen"})
