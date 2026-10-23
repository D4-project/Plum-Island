"""Regression checks for confirmed-batch dump import recovery."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "index_meili", Path(__file__).resolve().parents[1] / "tools/index_meili.py"
)
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


class ImportRecoveryTests(unittest.TestCase):
    """Exercise interruption and resume without external search services."""

    def test_resume_after_failed_batch(self):
        """Skip confirmed entries, retry uncertain work, retain cumulative counts."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.json").write_text(
                json.dumps([{"id": number} for number in range(5)]), encoding="utf-8"
            )
            args = SimpleNamespace(
                input_dir=directory,
                batch_size=2,
                task_timeout_ms=100,
                stat=False,
                progress=False,
                resume=False,
                checkpoint=None,
            )
            index = unittest.mock.Mock()
            index.add_documents.side_effect = [
                SimpleNamespace(task_uid=1),
                SimpleNamespace(task_uid=2),
            ]
            index.wait_for_task.side_effect = [
                SimpleNamespace(status="succeeded"),
                TimeoutError("interrupted"),
            ]
            client = unittest.mock.Mock()
            client.index.return_value = index
            backend = SimpleNamespace(Client=lambda *_: client)
            with (
                patch.object(IMPORTER, "parse_args", return_value=args),
                patch.object(
                    IMPORTER,
                    "load_config",
                    return_value={"OUT_MEILI_URL": "http://localhost:7700"},
                ),
                patch.object(IMPORTER, "print_indexing_status"),
                patch.dict("sys.modules", {"meilisearch": backend}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(TimeoutError):
                    IMPORTER.main()
                checkpoint = root / ".index-meili-checkpoint"
                self.assertEqual(json.loads(checkpoint.read_text())["indexed"], 2)
                args.resume = True
                index.reset_mock(side_effect=True)
                submitted = []

                def submit(batch):
                    """Snapshot mutable batches before the importer clears them."""
                    submitted.extend(doc["id"] for doc in batch)
                    return SimpleNamespace(task_uid=3)

                index.add_documents.side_effect = submit
                index.wait_for_task.return_value = SimpleNamespace(status="succeeded")
                IMPORTER.main()
                self.assertEqual(submitted, [2, 3, 4])
                self.assertEqual(json.loads(checkpoint.read_text())["indexed"], 5)
                submitted.clear()
                IMPORTER.main()
                self.assertEqual(submitted, [])

    def test_checkpoint_identity_and_validation(self):
        """Refuse changed sources, destinations and corrupt recovery positions."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "a.json"
            source.write_text('{"id": 1}', encoding="utf-8")
            identity = IMPORTER.import_identity(
                [source], root, "http://localhost", "plum"
            )
            checkpoint = root / ".checkpoint"
            IMPORTER.save_checkpoint(checkpoint, identity, 3, 2, 1)
            self.assertEqual(IMPORTER.load_checkpoint(checkpoint, identity), [3, 2, 1])
            with self.assertRaises(SystemExit):
                IMPORTER.load_checkpoint(checkpoint, dict(identity, index="other"))
            source.write_text('[{"id": 1}, {"id": 2}]', encoding="utf-8")
            changed = IMPORTER.import_identity(
                [source], root, "http://localhost", "plum"
            )
            with self.assertRaises(SystemExit):
                IMPORTER.load_checkpoint(checkpoint, changed)
            IMPORTER.save_checkpoint(checkpoint, identity, 3, 3, 1)
            with self.assertRaises(SystemExit):
                IMPORTER.load_checkpoint(checkpoint, identity)
            checkpoint.write_text("{", encoding="utf-8")
            with self.assertRaises(SystemExit):
                IMPORTER.load_checkpoint(checkpoint, identity)
            checkpoint.unlink()
            with self.assertRaises(SystemExit):
                IMPORTER.load_checkpoint(checkpoint, identity)

    def test_failed_task_preserves_batch(self):
        """A rejected task must never count as successfully imported work."""
        index = unittest.mock.Mock()
        index.wait_for_task.return_value = SimpleNamespace(
            uid=42, status="failed", error={"message": "invalid document"}
        )
        batch = [{"id": 1}]
        with self.assertRaises(RuntimeError):
            IMPORTER.flush_batch(index, batch, 100)
        self.assertEqual(batch, [{"id": 1}])
