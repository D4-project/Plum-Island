"""Foreground ingestion takes precedence between background writes."""

import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.utils import index_reconciliation as reconciliation


class IndexWritePriorityTest(unittest.TestCase):
    """Regression checks for index write priority test."""

    def test_kvrocks_uses_resp2(self):
        """Verify kvrocks uses resp2."""
        with patch("app.utils.kvrocks.redis.Redis") as connection:
            reconciliation.KVrocksIndexer(socket_timeout=10)
        self.assertEqual(connection.call_args.kwargs["protocol"], 2)

    def test_queue_snapshot_does_not_acquire_capture_barrier(self):
        """Verify queue snapshot does not acquire capture barrier."""
        raw = Mock()
        with patch.object(
            reconciliation,
            "write_barrier",
            side_effect=AssertionError("capture barrier acquired"),
        ):
            reconciliation.queue_snapshot(raw, {"revision": "one"}, full=True)
        raw.pipeline.return_value.execute.assert_called_once()

    def test_parse_outside_barrier_retries_when_generation_changes(self):
        """Verify parse outside barrier retries when generation changes."""
        raw = Mock()
        raw.get.side_effect = ["old", "new", "new", "new"]
        snapshots = [{"revision": "old"}, {"revision": "new"}]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"PLUM_INDEX_STATE_DIR": directory}
        ), patch.object(
            reconciliation, "read_json", side_effect=snapshots
        ), patch.object(
            reconciliation,
            "RulePlan",
            side_effect=lambda snapshot: SimpleNamespace(
                snapshot=snapshot, evaluate=lambda *_args, **_kwargs: ([], {})
            ),
        ), patch.object(
            reconciliation, "_ingest_document"
        ) as save:

            def parse(_source, _snapshot):
                """Provide the parse test fixture."""
                with reconciliation.file_lock(
                    reconciliation.state_directory() / "writes.lock", blocking=False
                ):
                    return {"uid": "one"}

            with patch.object(
                reconciliation, "parsed_source", side_effect=parse
            ) as parsed:
                reconciliation.ingest_sources(raw, [{"id": "one"}], {})
            self.assertEqual(parsed.call_count, 2)
            save.assert_called_once()
            self.assertEqual(save.call_args.args[2:4], ("new", snapshots[1]))

    def test_background_yields_to_waiting_ingestion(self):
        """Verify background yields to waiting ingestion."""
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"PLUM_INDEX_STATE_DIR": directory}
        ):
            waiting = threading.Event()
            foreground_done = threading.Event()
            order = []

            def foreground():
                """Provide the foreground test fixture."""
                waiting.set()
                with reconciliation.write_barrier():
                    order.append("ingestion")
                foreground_done.set()

            def background():
                """Provide the background test fixture."""
                with reconciliation.write_barrier(background=True):
                    order.append("retag")

            # Hold the write lock while foreground advertises its priority.
            with reconciliation.file_lock(
                reconciliation.state_directory() / "writes.lock"
            ):
                first = threading.Thread(target=foreground)
                first.start()
                self.assertTrue(waiting.wait(2))
                # Observe the actual foreground intent, rather than relying on sleep.
                for _ in range(200):
                    try:
                        with reconciliation.file_lock(
                            reconciliation.state_directory() / "ingestion.lock",
                            blocking=False,
                        ):
                            pass
                    except BlockingIOError:
                        break
                    threading.Event().wait(0.01)
                else:
                    self.fail("Foreground did not advertise pending ingestion")
                second = threading.Thread(target=background)
                second.start()
            self.assertTrue(foreground_done.wait(2))
            first.join(2)
            second.join(2)
            self.assertFalse(second.is_alive())
            self.assertEqual(order, ["ingestion", "retag"])
