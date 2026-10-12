"""Verify dump history before destructive replacement, without live services."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import fnmatch
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
with mock.patch.object(
    sys, "path", [str(ROOT / "tools"), str(ROOT / "webapp/app/utils"), *sys.path]
):
    importer = importlib.import_module("tools.reimport_port_dump")
    KVrocksIndexer = importlib.import_module("kvrocks").KVrocksIndexer
rebuild = importer.index_kvrocks


class MemoryPipeline:
    """Execute queued operations against an isolated in-memory store."""

    def __init__(self, store):
        self.store, self.calls = store, []

    def __getattr__(self, name):
        def queue(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self

        return queue

    def execute(self):
        """Return reads and apply writes in command order."""
        result = [
            getattr(self.store, name)(*args, **kwargs)
            for name, args, kwargs in self.calls
        ]
        self.calls.clear()
        return result


class MemoryStore:
    """Minimal Kvrocks command semantics needed for rebuild/index tests."""

    # pylint: disable=missing-function-docstring
    def __init__(self):
        self.data = {
            "doc:u": {"ip": "8.8.8.8", "first_seen": "100", "last_seen": "500"}
        }

    def pipeline(self, **_kwargs):
        return MemoryPipeline(self)

    def scan_iter(self, match, **_kwargs):
        return iter([key for key in self.data if fnmatch.fnmatchcase(key, match)])

    def delete(self, *keys):
        found = sum(key in self.data for key in keys)
        for key in keys:
            self.data.pop(key, None)
        return found

    def hgetall(self, key):
        return dict(self.data.get(key, {}))

    def smembers(self, key):
        return set(self.data.get(key, set()))

    def hset(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)

    def zadd(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)

    def sadd(self, key, value):
        self.data.setdefault(key, set()).add(value)

    def srem(self, key, value):
        self.data.setdefault(key, set()).discard(value)

    def set(self, key, value):
        self.data[key] = value


class ReimportHistoryTests(unittest.TestCase):
    """History validation must precede every backend mutation."""

    def setUp(self):
        # unittest owns this context and closes it even when setUp/test fails.
        # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        # pylint: enable=consider-using-with
        self.document = self.root / "renamed-file.json"
        self.document.write_text(
            json.dumps({"id": "u", "ip": "8.8.8.8", "body": {"endtime": 300}})
        )
        self.companion = self.document.with_suffix(".time")
        self.stack = self.enterContext(ExitStack())
        self.stack.enter_context(
            mock.patch.object(rebuild, "KVrocksIndexer", KVrocksIndexer)
        )
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def backend_mocks(self):
        """Keep real validation while isolating configuration and backend writes."""
        mocks = {
            "load_tool_config": mock.Mock(return_value=10),
            "validate_out_targets": mock.Mock(),
            "print_out_targets": mock.Mock(),
            "prepare_index_kvrocks_runtime": mock.Mock(),
            "replace_meili_from_dump": mock.Mock(),
            "rebuild_kvrocks_from_dump": mock.Mock(return_value=(1, 1, 0)),
        }
        self.stack.enter_context(mock.patch.multiple(importer, **mocks))
        return mocks

    def run_import(self, *extra):
        """Exercise the real CLI control flow with a disposable dump."""
        importer.main(
            [
                "--input-dir",
                str(self.root),
                "--workers",
                "1",
                "--areyousure_yes",
                *extra,
            ]
        )

    def test_bad_history_stops_before_both_backends(self):
        """Missing, partial and malformed dates cannot reach replacement calls."""
        backends = self.backend_mocks()
        contents = (
            None,
            "{broken",
            "[]",
            "{}",
            '{"first_seen": 100}',
            '{"last_seen": 500}',
            '{"first_seen": null, "last_seen": 500}',
            '{"first_seen": true, "last_seen": 500}',
            '{"first_seen": -1, "last_seen": 500}',
            '{"first_seen": 500, "last_seen": 100}',
            '{"first_seen": "NaN", "last_seen": 500}',
            '{"first_seen": 100, "last_seen": "Infinity"}',
        )
        for content in contents:
            with self.subTest(content=content):
                self.companion.unlink(missing_ok=True)
                if content is not None:
                    self.companion.write_text(content)
                with self.assertRaisesRegex(SystemExit, "Incomplete dump history"):
                    self.run_import()
        backends["replace_meili_from_dump"].assert_not_called()
        backends["rebuild_kvrocks_from_dump"].assert_not_called()

    def test_snapshot_validated_once_before_meili_and_passed_to_rebuild(self):
        """Use document IDs, retaining validated dates through Meili replacement."""
        self.companion.write_text('{"first_seen": 100, "last_seen": 500}')
        backends = self.backend_mocks()
        backends["replace_meili_from_dump"].side_effect = (
            lambda *_args: self.companion.unlink()
        )
        with mock.patch.object(
            importer, "load_time_snapshot", wraps=importer.load_time_snapshot
        ) as load:
            self.run_import()
        self.assertEqual(load.call_count, 1)
        backends["rebuild_kvrocks_from_dump"].assert_called_once_with(
            self.root, 10, 1, 1, seen_snapshot={"u": (100, 500)}
        )

    def test_explicit_override_warns_and_allows_scan_date_fallback(self):
        """The existing destruction confirmation alone never bypasses history checks."""
        backends = self.backend_mocks()
        warning = io.StringIO()
        with redirect_stderr(warning):
            self.run_import("--allow-history-loss")
        self.assertIn("historical bounds may be lost", warning.getvalue())
        backends["replace_meili_from_dump"].assert_called_once()
        self.assertEqual(
            backends["rebuild_kvrocks_from_dump"].call_args.kwargs["seen_snapshot"], {}
        )

    def test_meili_only_does_not_require_history(self):
        """Skipping Kvrocks leaves historical metadata untouched."""
        backends = self.backend_mocks()
        self.run_import("--skip-kvrocks")
        backends["replace_meili_from_dump"].assert_called_once()
        backends["rebuild_kvrocks_from_dump"].assert_not_called()
        backends["prepare_index_kvrocks_runtime"].assert_not_called()

    def test_duplicate_uid_merges_bounds_and_accepts_epoch_zero(self):
        """Different filenames with one document ID cannot overwrite its history."""
        self.companion.write_text('{"first_seen": 100, "last_seen": 500}')
        other = self.root / "another.json"
        other.write_text(self.document.read_text())
        other.with_suffix(".time").write_text('{"first_seen": 0, "last_seen": 300}')
        self.assertEqual(importer.load_time_snapshot(self.root), {"u": (0, 500)})

    def test_invalid_document_is_rejected_even_with_history_override(self):
        """Do not assign dates to an absent or unusable document identity."""
        backends = self.backend_mocks()
        self.document.write_text("{}")
        with self.assertRaisesRegex(SystemExit, "Invalid dump document"):
            self.run_import("--allow-history-loss")
        backends["replace_meili_from_dump"].assert_not_called()
        backends["rebuild_kvrocks_from_dump"].assert_not_called()

    def test_standard_rebuild_preserves_hashes_and_date_indexes(self):
        """The normal rebuild retains historical bounds without a RAM snapshot."""
        indexer = KVrocksIndexer.__new__(KVrocksIndexer)
        indexer.r = MemoryStore()
        self.assertIsNone(rebuild.rebuild_kvrocks(indexer))
        indexer.add_documents_batch([{"uid": "u", "ip": "8.8.8.8", "last_seen": 300}])
        self.assertEqual(indexer.r.hgetall("doc:u")["first_seen"], "100")
        self.assertEqual(indexer.r.hgetall("doc:u")["last_seen"], "500")
        self.assertEqual(indexer.r.data["first_seen_index"]["u"], 100)
        self.assertEqual(indexer.r.data["last_seen_index"]["u"], 500)

    def test_dump_rebuild_restores_validated_history_after_deletion(self):
        """Exercise companion loading, deletion, snapshot application and indexing."""
        self.companion.write_text('{"first_seen": 100, "last_seen": 500}')
        store = MemoryStore()
        with mock.patch.object(
            KVrocksIndexer, "__init__", lambda obj, *_args: setattr(obj, "r", store)
        ), mock.patch.multiple(
            rebuild,
            load_active_tag_rules=mock.Mock(return_value=([], 0)),
            install_graceful_interrupt_handler=mock.Mock(),
            STOP_REQUESTED=False,
            parse_json=lambda doc, *_args, **_kwargs: {
                "uid": doc["id"],
                "ip": doc["ip"],
                "last_seen": doc["body"]["endtime"],
            },
            prepare_kvrocks_document=lambda _raw, parsed, **_kwargs: parsed,
        ):
            self.assertEqual(
                importer.rebuild_kvrocks_from_dump(self.root, 10, 1, 1), (1, 1, 0)
            )
        self.assertEqual(
            store.hgetall("doc:u"),
            {"ip": "8.8.8.8", "first_seen": "100", "last_seen": "500"},
        )
        self.assertEqual(store.data["first_seen_index"]["u"], 100)
        self.assertEqual(store.data["last_seen_index"]["u"], 500)
