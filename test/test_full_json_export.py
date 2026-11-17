"""Exercise the JSON export worker without Flask startup or live backends."""

import ast
from contextlib import nullcontext
import json
import logging
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test.test_kvrocks_search import make_indexer
from tagrules import normalize_tags

# pylint: disable=protected-access,missing-function-docstring

ROOT = Path(__file__).resolve().parents[1]


def export_view(indexer, index, directory):
    """Load actual worker and document loader methods, mocking only dependencies."""
    tree = ast.parse((ROOT / "webapp/app/views.py").read_text())
    view = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "KVSearchView"
    )
    names = {
        "_build_full_export_payload",
        "_is_missing_meili_document",
        "_load_meili_document",
        "_iter_export_tags",
        "_run_full_export_job",
    }
    view.bases = []
    view.body = [
        node
        for node in view.body
        if (isinstance(node, ast.FunctionDef) and node.name in names)
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "EXPORT_TAG_BATCH_SIZE"
                for target in node.targets
            )
        )
    ]
    namespace = {
        "app": SimpleNamespace(app_context=nullcontext),
        "db": SimpleNamespace(
            app=SimpleNamespace(config={"KVROCKS_HOST": "unused", "KVROCKS_PORT": 0})
        ),
        "client": SimpleNamespace(index=lambda _name: index),
        "KVrocksIndexer": lambda *_args: indexer,
        "MeilisearchApiError": LookupError,
        "normalize_tags": normalize_tags,
        "utcnow_iso": lambda: "2026-11-16T12:00:00+00:00",
        "logger": logging.getLogger(__name__),
        "json": json,
        "os": os,
    }
    module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
    exec(  # pylint: disable=exec-used
        compile(module, "<isolated JSON export>", "exec"), namespace
    )
    result = namespace["KVSearchView"]
    state = {"query": "port:443", "from_ts": 100, "to_ts": 300}
    result._get_job_state = Mock(return_value=state)
    result._set_job_state = Mock(side_effect=lambda _job, **data: state.update(data))
    result._add_job_warning = Mock()
    result._get_export_jobs_folder = Mock(return_value=directory)
    return result, state


class FullJsonExportTest(unittest.TestCase):
    """Verify serialized per-scan tags, bounded reads and failure behavior."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(temporary.cleanup)
        self.directory = temporary.name
        self.indexer = make_indexer()
        self.index = Mock()
        self.index.get_document.side_effect = lambda uid: SimpleNamespace(id=uid)
        self.view, self.state = export_view(self.indexer, self.index, self.directory)

    def run_export(self, results):
        self.view.execute_search = Mock(return_value=results)
        self.view._run_full_export_job("test-job")

    def payload(self):
        return json.loads(Path(self.state["file_path"]).read_text(encoding="utf-8"))

    def test_per_uid_tags_are_normalized_sorted_and_scoped_to_search(self):
        self.indexer.r.sets.update(
            {
                "ip:192.0.2.1": {"old", "new", "excluded"},
                "tags:old": {"tag:Vendor:Mikrotik", "proto:ssh", "vendor:mikrotik"},
                "tags:new": {"proto:https", "type:router"},
                "tags:excluded": {"vendor:excluded"},
            }
        )
        results = {
            "status": True,
            "time_range": {"from_ts": 100, "to_ts": 300},
            "results": {"192.0.2.1": ["old", "new"], "2001:db8::1": ["untagged"]},
            "timestamps": {"192.0.2.1": {"old": {"first_seen": 100, "last_seen": 200}}},
        }
        self.run_export(results)
        payload = self.payload()
        old, new = payload["results"]["192.0.2.1"]
        self.assertEqual(old["tags"], ["proto:ssh", "vendor:mikrotik"])
        self.assertEqual(new["tags"], ["proto:https", "type:router"])
        self.assertEqual(old["document"], {"id": "old"})
        self.assertEqual((old["first_seen"], old["last_seen"]), (100, 200))
        self.assertEqual(payload["results"]["2001:db8::1"][0]["tags"], [])
        self.assertEqual(payload["time_range"], results["time_range"])
        self.view.execute_search.assert_called_once_with("port:443", 100, 300)
        reads = [key for _, batch in self.indexer.r.batches for _, key in batch]
        self.assertEqual(reads, ["tags:old", "tags:new", "tags:untagged"])
        self.assertEqual(self.state["status"], "done")
        self.assertEqual(self.state["processed_uids"], 3)

    def test_missing_meilisearch_document_preserves_tags_and_warning(self):
        self.indexer.r.sets["tags:missing"] = {"proto:ssh"}
        self.index.get_document.side_effect = LookupError("document_not_found")
        with self.assertLogs(__name__, level="WARNING"):
            self.run_export(
                {
                    "status": True,
                    "results": {"192.0.2.1": ["missing"]},
                    "timestamps": {},
                }
            )
        entry = self.payload()["results"]["192.0.2.1"][0]
        self.assertEqual(entry["tags"], ["proto:ssh"])
        self.assertIsNone(entry["document"])
        self.assertEqual(entry["warning"], "document_not_found")
        self.view._add_job_warning.assert_called_once()
        self.assertEqual(self.state["status"], "done")

    def test_large_host_history_uses_bounded_nontransactional_batches(self):
        uids = [f"scan-{number}" for number in range(1001)]
        self.indexer.r.sets.update({f"tags:{uid}": {"proto:ssh"} for uid in uids})
        self.run_export(
            {"status": True, "results": {"192.0.2.1": uids}, "timestamps": {}}
        )
        entries = self.payload()["results"]["192.0.2.1"]
        self.assertEqual([entry["uid"] for entry in entries], uids)
        self.assertTrue(all(entry["tags"] == ["proto:ssh"] for entry in entries))
        self.assertEqual(
            [len(commands) for _, commands in self.indexer.r.batches], [500, 500, 1]
        )
        self.assertTrue(
            all(not transaction for transaction, _ in self.indexer.r.batches)
        )

    def test_kvrocks_failure_fails_export_without_publishing_incomplete_file(self):
        self.indexer.r.pipeline = Mock(side_effect=ConnectionError("Kvrocks offline"))
        with self.assertLogs(__name__, level="ERROR"):
            self.run_export(
                {"status": True, "results": {"192.0.2.1": ["scan"]}, "timestamps": {}}
            )
        self.assertEqual(self.state["status"], "error")
        self.assertEqual(list(Path(self.directory).iterdir()), [])
        self.index.get_document.assert_not_called()

    def test_empty_search_exports_empty_results_without_reading_tags(self):
        self.run_export({"status": True, "results": {}, "timestamps": {}})
        self.assertEqual(self.payload()["results"], {})
        self.assertEqual(self.state["status"], "done")
        self.assertEqual(self.indexer.r.batches, [])
        self.index.get_document.assert_not_called()
