"""Accepted import tasks survive long waits and process interruptions."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from meilisearch.errors import MeilisearchTimeoutError

SPEC = importlib.util.spec_from_file_location(
    "index_meili", Path(__file__).resolve().parents[1] / "tools/index_meili.py"
)
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


def completed_task(uid, count, **changes):
    """Return the metadata used to confirm a submitted batch."""
    values = {
        "uid": uid,
        "index_uid": "plum",
        "type": "documentAdditionOrUpdate",
        "status": "succeeded",
        "details": {"receivedDocuments": count},
        "error": None,
    }
    return SimpleNamespace(**dict(values, **changes))


class ImportRecoveryTests(
    unittest.TestCase
):  # pylint: disable=too-many-instance-attributes
    """Exercise the CLI and durable task handoff without external services."""

    def setUp(self):
        """Isolate input, checkpoint and a backend that records submitted IDs."""
        self.root = Path(
            self.enterContext(
                tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
            )
        )
        self.source = self.root / "a.json"
        self.source.write_text(
            json.dumps([{"id": n} for n in range(5)]), encoding="utf-8"
        )
        self.path = self.root / ".index-meili-checkpoint"
        self.identity = IMPORTER.import_identity(
            [self.source], self.root, "http://localhost:7700", "plum"
        )
        self.args = SimpleNamespace(
            input_dir=str(self.root),
            batch_size=2,
            task_timeout_ms=0,
            stat=False,
            progress=False,
            resume=False,
            checkpoint=None,
        )
        self.index = Mock()
        self.submitted = []
        self.sizes = {}

        def submit(batch):
            uid = len(self.sizes) + 1
            self.sizes[uid] = len(batch)
            self.submitted.extend(doc["id"] for doc in batch)
            return SimpleNamespace(task_uid=uid)

        self.index.add_documents.side_effect = submit
        self.index.wait_for_task.side_effect = lambda uid, **_: completed_task(
            uid, self.sizes[uid]
        )
        client = Mock()
        client.index.return_value = self.index
        self.enterContext(patch("meilisearch.Client", return_value=client))
        self.enterContext(patch.object(IMPORTER, "parse_args", return_value=self.args))
        self.enterContext(
            patch.object(
                IMPORTER,
                "load_config",
                return_value={"OUT_MEILI_URL": "http://localhost:7700"},
            )
        )
        self.enterContext(patch.object(IMPORTER, "print_indexing_status"))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def journal(self):
        """Create an empty import checkpoint."""
        journal = IMPORTER.ImportCheckpoint(
            self.path, self.identity, {key: 0 for key in IMPORTER.COUNTERS}
        )
        journal.save()
        return journal

    def state(self):
        """Read the state that a fresh importer would see."""
        return IMPORTER.load_checkpoint(self.path, self.identity)

    def test_resume_waits_for_accepted_batch_without_resubmitting(self):
        """Resume inside a multi-document file and keep cumulative counters."""
        self.index.wait_for_task.side_effect = [
            completed_task(1, 2),
            TimeoutError("interrupted"),
        ]
        with self.assertRaises(TimeoutError):
            IMPORTER.main()
        self.assertEqual(self.state()["indexed"], 2)
        self.assertEqual(self.state()["pending"]["task_uid"], 2)
        self.assertEqual(self.state()["pending"]["indexed"], 4)
        self.args.resume = True
        self.submitted.clear()
        self.index.wait_for_task.side_effect = lambda uid, **_: completed_task(
            uid, self.sizes[uid]
        )
        IMPORTER.main()
        self.assertEqual(self.submitted, [4])
        self.assertEqual(self.state()["indexed"], 5)
        self.assertIsNone(self.state().get("pending"))
        self.submitted.clear()
        IMPORTER.main()
        self.assertEqual(self.submitted, [])

    def test_default_wait_survives_fifteen_minutes(self):
        """Several polling windows still refer to the original accepted task."""
        journal = self.journal()
        self.index.wait_for_task.side_effect = [
            MeilisearchTimeoutError("still processing"),
            completed_task(1, 1),
        ]
        with patch.object(IMPORTER.time, "monotonic", side_effect=[0, 0, 960, 960]):
            journal.flush(self.index, [{"id": 1}], 1, 0)
        self.index.add_documents.assert_called_once()
        self.assertEqual(
            [call.args[0] for call in self.index.wait_for_task.call_args_list], [1, 1]
        )
        self.assertEqual(self.state()["indexed"], 1)
        self.assertIn("960s", self.output.getvalue())

    def test_explicit_wait_timeout_preserves_task_for_resume(self):
        """An optional wait limit stops locally without advancing or resending."""
        journal = self.journal()
        journal.task_timeout_ms = 1000
        self.index.wait_for_task.side_effect = MeilisearchTimeoutError(
            "still processing"
        )
        with patch.object(IMPORTER.time, "monotonic", side_effect=[0, 0, 1, 1]):
            with self.assertRaisesRegex(SystemExit, "task 1.*--continue"):
                journal.flush(self.index, [{"id": 1}], 1, 0)
        self.assertEqual(self.state()["indexed"], 0)
        self.assertEqual(self.state()["pending"]["task_uid"], 1)
        resumed = IMPORTER.ImportCheckpoint(self.path, self.identity, self.state())
        self.index.wait_for_task.side_effect = lambda uid, **_: completed_task(uid, 1)
        resumed.finish_pending(self.index)
        self.index.add_documents.assert_called_once()
        self.assertEqual(self.state()["indexed"], 1)

    def test_ctrl_c_keeps_uid_and_confirmed_counters(self):
        """Ctrl+C cannot erase accepted work from the durable checkpoint."""
        journal = self.journal()
        self.index.wait_for_task.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            journal.flush(self.index, [{"id": 1}], 1, 0)
        self.assertEqual(self.state()["indexed"], 0)
        self.assertEqual(self.state()["pending"]["task_uid"], 1)

    def test_submission_response_loss_blocks_automatic_resubmission(self):
        """The server may accept POST even if the client never receives its UID."""
        journal = self.journal()
        self.index.add_documents.side_effect = TimeoutError("response lost")
        with self.assertRaises(TimeoutError):
            journal.flush(self.index, [{"id": 1}], 1, 0)
        self.assertIsNone(self.state()["pending"]["task_uid"])
        self.args.resume = True
        with self.assertRaisesRegex(SystemExit, "before its task UID"):
            IMPORTER.main()
        self.index.add_documents.assert_called_once()

    def test_uid_checkpoint_failure_keeps_submission_intent(self):
        """A disk failure after POST must not look like a safe unsubmitted batch."""
        journal = self.journal()
        save = journal.save

        def fail_after_post(**changes):
            if changes["pending"]["task_uid"] is not None:
                raise OSError("disk unavailable")
            save(**changes)

        with patch.object(journal, "save", side_effect=fail_after_post):
            with self.assertRaises(OSError):
                journal.flush(self.index, [{"id": 1}], 1, 0)
        resumed = IMPORTER.ImportCheckpoint(self.path, self.identity, self.state())
        with self.assertRaisesRegex(SystemExit, "before its task UID"):
            resumed.finish_pending(self.index)
        self.index.add_documents.assert_called_once()

    def test_intent_checkpoint_failure_prevents_submission(self):
        """No POST occurs unless recovery intent was persisted first."""
        journal = self.journal()
        with patch.object(journal, "save", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                journal.flush(self.index, [{"id": 1}], 1, 0)
        self.index.add_documents.assert_not_called()

    def test_failed_or_canceled_task_allows_a_later_retry(self):
        """Only a known server failure may release the pending submission."""
        for status in ("failed", "canceled"):
            with self.subTest(status=status):
                journal = self.journal()
                self.index.wait_for_task.side_effect = (
                    lambda uid, status=status, **_: completed_task(
                        uid, 1, status=status, error={"message": "rejected"}
                    )
                )
                batch = [{"id": 1}]
                with self.assertRaisesRegex(
                    RuntimeError, "Confirmed counters unchanged"
                ):
                    journal.flush(self.index, batch, 1, 0)
                self.assertEqual(batch, [{"id": 1}])
                self.assertEqual(self.state()["indexed"], 0)
                self.assertIsNone(self.state().get("pending"))

    def test_task_metadata_mismatch_does_not_advance_checkpoint(self):
        """An unrelated task cannot confirm a saved import position."""
        journal = self.journal()
        self.index.wait_for_task.side_effect = lambda uid, **_: completed_task(
            uid, 1, index_uid="other"
        )
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            journal.flush(self.index, [{"id": 1}], 1, 0)
        self.assertEqual(self.state()["indexed"], 0)
        self.assertIsNotNone(self.state()["pending"])

    def test_parse_errors_keep_raw_cursor_during_pending_task_resume(self):
        """Failed JSON entries count toward the raw position, not indexed count."""
        self.source.write_text(
            json.dumps([{"id": 0}, "bad", {"id": 1}, {"id": 2}]), encoding="utf-8"
        )
        self.index.wait_for_task.side_effect = TimeoutError("interrupted")
        with self.assertRaises(TimeoutError):
            IMPORTER.main()
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["pending"]["processed"], 3)
        self.assertEqual(saved["pending"]["errors"], 1)
        self.submitted.clear()
        self.args.resume = True
        self.index.wait_for_task.side_effect = lambda uid, **_: completed_task(
            uid, self.sizes[uid]
        )
        IMPORTER.main()
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(self.submitted, [2])
        self.assertEqual([saved[key] for key in IMPORTER.COUNTERS], [4, 3, 1])

    def test_legacy_checkpoint_remains_resumable(self):
        """Version-one counters without pending metadata keep their old position."""
        IMPORTER.save_checkpoint(self.path, self.identity, 2, 2, 0)
        self.args.resume = True
        IMPORTER.main()
        self.assertEqual(self.submitted, [2, 3, 4])
        self.assertEqual(self.state()["indexed"], 5)

    def test_restart_cannot_overwrite_pending_submission(self):
        """Forgetting --continue must not discard an accepted task UID."""
        journal = self.journal()
        journal.save(pending={"task_uid": 1, "processed": 1, "indexed": 1, "errors": 0})
        before = self.path.read_text(encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "pending task"):
            IMPORTER.main()
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)
        self.index.add_documents.assert_not_called()

    def test_checkpoint_identity_and_validation(self):
        """Reject changed dumps, destinations and invalid committed/pending counts."""
        IMPORTER.save_checkpoint(self.path, self.identity, 3, 2, 1)
        self.assertEqual([self.state()[key] for key in IMPORTER.COUNTERS], [3, 2, 1])
        with self.assertRaises(SystemExit):
            IMPORTER.load_checkpoint(self.path, dict(self.identity, index="other"))
        self.source.write_text('[{"id": 1}]', encoding="utf-8")
        changed = IMPORTER.import_identity(
            [self.source], self.root, "http://localhost:7700", "plum"
        )
        with self.assertRaises(SystemExit):
            IMPORTER.load_checkpoint(self.path, changed)
        valid = {"task_uid": 1, "processed": 5, "indexed": 4, "errors": 1}
        for invalid in (
            [],
            dict(valid, task_uid=True),
            dict(valid, processed=6),
            dict(valid, indexed=2),
            dict(valid, errors=-1),
        ):
            IMPORTER.save_checkpoint(self.path, self.identity, 3, 2, 1, pending=invalid)
            with self.assertRaises(SystemExit):
                self.state()
        IMPORTER.save_checkpoint(self.path, self.identity, 3, 3, 1)
        with self.assertRaises(SystemExit):
            self.state()
        self.path.write_text("{", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.state()
        self.path.unlink()
        with self.assertRaises(SystemExit):
            self.state()
