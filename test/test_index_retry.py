"""Backend outages back off without losing checkpoints or masking data errors."""

import json
import logging
import os
import unittest
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import meilisearch
import redis
from app.utils.index_generations import ACTIVE, CONTROL
from app.utils.index_pacing import PacedReconciliationWorker
from app.utils.index_reconciliation import ReconciliationWorker, SnapshotInvalid
from app.utils.index_retry import retry_delay, transient_error
from app.utils.index_sources import ReconciliationHttpRequests, SourceDocuments
from app.utils.index_supervisor import IndexSupervisor
from meilisearch.errors import MeilisearchApiError, MeilisearchCommunicationError
from requests import Response, Session
from tools.reconcile_index import configure_http_logging


class MeilisearchFixtureHandler(BaseHTTPRequestHandler):
    """Serve minimal HTTP/1.1 source reads over a real persistent socket."""

    protocol_version = "HTTP/1.1"
    wbufsize = -1
    disable_nagle_algorithm = True

    def log_request(self, code="-", size="-"):
        """Keep fixture output quiet."""

    def _reply(self, payload, *, status=200, close=False, truncate=False):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body) + int(truncate)))
        if close or truncate:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # pylint: disable=invalid-name
        """Return a document or exercise connection closure."""
        uid = urlsplit(self.path).path.rsplit("/", 1)[1]
        self.server.reads.append(("GET", uid))
        if uid == "missing":
            self._reply(
                {"message": "Document not found", "code": "document_not_found"},
                status=404,
            )
            return
        self._reply(
            {"id": uid, "ip": "93.184.216.34"},
            close=uid == "close",
            truncate=uid == "truncate",
        )

    def do_POST(self):  # pylint: disable=invalid-name
        """Return inventory or a reversed list of requested source documents."""
        query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        uids = query.get("ids")
        self.server.reads.append(("POST", query))
        results = (
            [
                {"id": uid, "ip": "93.184.216.34"}
                for uid in reversed(uids)
                if uid != "missing"
            ]
            if uids is not None
            else [{"id": "one"}]
        )
        self._reply(
            {
                "results": results,
                "offset": 0,
                "limit": query["limit"],
                "total": len(results),
            }
        )


class MeilisearchFixture(ThreadingHTTPServer):
    """Count TCP connections accepted by the HTTP fixture."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), MeilisearchFixtureHandler)
        self.connections = 0
        self.reads = []

    def get_request(self):
        """Count new sockets separately from HTTP requests."""
        connection, address = super().get_request()
        self.connections += 1
        return connection, address


class ReconciliationTransportTest(unittest.TestCase):
    """Use the real SDK and session with isolated source reads."""

    def setUp(self):
        self.server = self.enterContext(MeilisearchFixture())
        thread = Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)
        session = self.enterContext(Session())
        session.trust_env = False
        index = meilisearch.Client(
            f"http://127.0.0.1:{self.server.server_port}", "fixture", timeout=2
        ).index("plum")
        index.http = ReconciliationHttpRequests(index.config, session)
        self.source = SourceDocuments(index)

    def test_document_gets_and_inventory_post_share_a_connection(self):
        """Document and inventory reads reuse the same TCP connection."""
        self.assertEqual(self.source.get_document("one").id, "one")
        self.assertEqual(self.source.get_documents({"limit": 1}).results[0].id, "one")
        self.assertEqual(self.source.get_document("two").id, "two")
        self.assertEqual(self.server.connections, 1)

    def test_closed_connection_reopens_and_truncated_response_is_retryable(self):
        """Reconnect after a close and classify a lost response as transient."""
        self.source.get_document("close")
        self.source.get_document("two")
        self.assertEqual(self.server.connections, 2)
        with self.assertRaises(MeilisearchCommunicationError) as raised:
            self.source.get_document("truncate")
        self.assertTrue(transient_error(raised.exception))
        self.assertEqual(self.source.get_document("three").id, "three")
        self.assertEqual(self.server.connections, 3)

    def test_batch_maps_sources_by_id_and_preserves_missing_document_error(self):
        """The original 404 is raised for the absent UID when it is consumed."""
        self.source.batch_size = 32
        self.source.use_candidates(["newest", "missing", "older"])
        self.assertEqual(self.source.get_document("newest").id, "newest")
        with self.assertRaises(MeilisearchApiError) as raised:
            self.source.get_document("missing")
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.code, "document_not_found")
        self.assertFalse(transient_error(raised.exception))
        self.assertEqual(self.source.get_document("older").id, "older")
        self.assertEqual(
            self.server.reads,
            [
                ("POST", {"ids": ["newest", "missing", "older"], "limit": 3}),
                ("GET", "missing"),
            ],
        )


class ReconciliationHttpLoggingTest(unittest.TestCase):
    """Keep per-request traces separate from normal worker DEBUG logs."""

    def test_http_debug_requires_explicit_opt_in(self):
        """Opt in to traces while retaining warning and root log levels."""
        root = logging.getLogger()
        http = logging.getLogger("urllib3.connectionpool")
        self.addCleanup(root.setLevel, root.level)
        self.addCleanup(http.setLevel, http.level)
        root.setLevel(logging.DEBUG)
        configure_http_logging({})
        self.assertFalse(http.isEnabledFor(logging.DEBUG))
        self.assertTrue(http.isEnabledFor(logging.WARNING))
        self.assertTrue(root.isEnabledFor(logging.DEBUG))
        config = {"TAG_RECONCILIATION_HTTP_DEBUG": True}
        configure_http_logging(config)
        self.assertTrue(http.isEnabledFor(logging.DEBUG))
        root.setLevel(logging.INFO)
        configure_http_logging(config)
        self.assertFalse(http.isEnabledFor(logging.DEBUG))


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
