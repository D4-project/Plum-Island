"""Dump migration checks on temporary files, without live service access."""

import copy
import importlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools import migrate_smarthash as migration


class MigrationTests(unittest.TestCase):
    """Verify lossless history merging and fail-closed preparation."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"
        # Pipeline tests work with old/new installed libraries. The guard itself
        # is separately tested; real date normalization belongs to nmap2json.
        guard = mock.patch.object(
            migration, "check_library", return_value="test-library"
        )
        guard.start()
        self.addCleanup(guard.stop)

    def document(self, uid, observed, banner="220 stable ESMTP"):
        """Synthetic port-scoped source with stable meaningful content."""
        return {
            "id": uid,
            "ip": "2001:db8::1",
            "body": {
                "endtime": observed,
                "ports": [
                    {
                        "protocol": "tcp",
                        "portid": "25",
                        "scripts": [{"id": "banner", "output": banner}],
                    }
                ],
            },
        }

    def write(self, doc, first=10, last=30):
        """Write one input document and its exact history."""
        path = self.source / f"{doc['id']}.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        path.with_suffix(".time").write_text(
            json.dumps({"first_seen": first, "last_seen": last}), encoding="utf-8"
        )
        return path

    def test_merge_history_and_newest_independent_of_order(self):
        """Keep earliest/latest bounds, but choose payload by observation time."""
        old = self.document("old", 100)
        new = self.document("new", 200)
        self.write(old, 1, 500)
        self.write(new, 20, 300)
        summary = migration.prepare(self.source, self.output)
        self.assertEqual(summary["merged_documents"], 1)
        paths = list(self.output.rglob("*.json"))
        self.assertEqual(len(paths), 1)
        saved = json.loads(paths[0].read_text())
        self.assertEqual(saved["body"]["endtime"], 200)
        self.assertEqual(
            json.loads(paths[0].with_suffix(".time").read_text()),
            {"first_seen": 1, "last_seen": 500},
        )
        self.assertEqual(
            len((self.output / "uid-map.jsonl").read_text().splitlines()), 2
        )
        # Swap traversal order by swapping filenames, while retaining old IDs.
        (self.source / "old.json").write_text(json.dumps(new))
        (self.source / "new.json").write_text(json.dumps(old))
        other = self.root / "other"
        migration.prepare(self.source, other)
        self.assertEqual(json.loads(next(other.rglob("*.json")).read_text()), saved)

    def test_second_migration_keeps_ids(self):
        """Serialization of the migrated dump must not reorder hashed keys."""
        self.write(self.document("first", 100))
        migration.prepare(self.source, self.output)
        again = self.root / "again"
        migration.prepare(self.output, again)
        self.assertEqual(
            [p.name for p in self.output.rglob("*.json")],
            [p.name for p in again.rglob("*.json")],
        )

    def test_different_content_stays_separate(self):
        self.write(self.document("first", 100, "server v1"))
        self.write(self.document("second", 200, "server v2"))
        self.assertEqual(
            migration.prepare(self.source, self.output)["unique_documents"], 2
        )

    def test_dry_run_no_output(self):
        self.write(self.document("first", 100))
        self.assertEqual(
            migration.prepare(self.source, self.output, dry_run=True)[
                "unique_documents"
            ],
            1,
        )
        self.assertFalse(self.output.exists())

    def test_incomplete_history_aborts_before_output(self):
        for first, last in (
            (None, 30),
            (10, None),
            ("bad", 30),
            (40, 30),
            (float("nan"), 30),
        ):
            with self.subTest(first=first, last=last):
                self.write(self.document("first", 100), first, last)
                with self.assertRaises(ValueError):
                    migration.prepare(self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_missing_companion_aborts(self):
        path = self.write(self.document("first", 100))
        path.with_suffix(".time").unlink()
        with self.assertRaises(FileNotFoundError):
            migration.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_readonly_source_history(self):
        path = self.write(self.document("first", 100))
        path.with_suffix(".time").unlink()
        client = mock.Mock()
        client.hgetall.return_value = {"first_seen": "10", "last_seen": "30"}
        migration.prepare(self.source, self.output, client=client)
        self.assertEqual(client.mock_calls, [mock.call.hgetall("doc:first")])

    def test_existing_or_nested_output_refused(self):
        self.output.mkdir()
        for output in (self.output, self.source, self.source / "child", self.root):
            with self.subTest(output=output), self.assertRaises(ValueError):
                migration.prepare(self.source, output)

    def test_empty_or_malformed_input_refused(self):
        with self.assertRaises(ValueError):
            migration.prepare(self.source, self.output)
        (self.source / "bad.json").write_text("[42]")
        with self.assertRaises(ValueError):
            migration.prepare(self.source, self.output, client=mock.Mock())
        self.assertFalse(self.output.exists())

    def test_raw_port_unchanged(self):
        doc = self.document("first", 100, r"220 mail\0d\0a")
        original = copy.deepcopy(doc)
        result = list(migration.port_documents(doc))[0]
        self.assertEqual(doc, original)
        self.assertEqual(result["body"]["ports"], doc["body"]["ports"])

    def test_apply_requires_successful_preparation(self):
        with mock.patch.object(migration.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                migration.main(
                    [
                        "--input-dir",
                        str(self.source),
                        "--output-dir",
                        str(self.output),
                        "--use-time-companions",
                        "--apply-out",
                    ]
                )
            run.assert_not_called()
            self.write(self.document("first", 100))
            migration.main(
                [
                    "--input-dir",
                    str(self.source),
                    "--output-dir",
                    str(self.output),
                    "--use-time-companions",
                    "--apply-out",
                ]
            )
            self.assertEqual(
                run.call_args.args[0][-2:], ["--meili-replace-mode", "swap"]
            )
            self.assertTrue((self.output / "migration.manifest").is_file())

    def test_cli_uses_configured_in_kvrocks_by_default(self):
        config_path = self.root / "config.yaml"
        config_path.write_text(
            "IN_KVROCKS_HOST: source.example\n"
            "IN_KVROCKS_PORT: 6670\n"
            "IN_KVROCKS_PASSWORD: test-password\n"
            "OUT_KVROCKS_HOST: destination.example\n"
            "OUT_KVROCKS_PORT: 6680\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(migration, "CONFIG_PATH", config_path),
            mock.patch.object(migration.redis, "Redis") as redis_client,
            mock.patch.object(migration, "prepare", return_value={}) as prepare,
        ):
            migration.main(
                ["--input-dir", str(self.source), "--output-dir", str(self.output)]
            )
        redis_client.assert_called_once_with(
            host="source.example",
            port=6670,
            password="test-password",
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=10,
        )
        self.assertIs(prepare.call_args.kwargs["client"], redis_client.return_value)
        redis_client.return_value.close.assert_called_once()

    def test_dry_run_cannot_apply(self):
        with mock.patch.object(migration.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                migration.main(
                    [
                        "--input-dir",
                        str(self.source),
                        "--output-dir",
                        str(self.output),
                        "--dry-run",
                        "--apply-out",
                    ]
                )
            run.assert_not_called()

    def test_timestamp_formats(self):
        self.assertEqual(migration.timestamp("2026-01-01T00:00:00Z"), 1767225600)
        self.assertEqual(migration.timestamp(1767225600000), 1767225600)


class LibraryGuardTests(unittest.TestCase):
    """A migration must not silently use obsolete smarthash code."""

    def test_old_library_refused(self):
        with mock.patch.object(
            migration.smarthash, "port_smart_hash", side_effect=["one", "two"]
        ):
            with self.assertRaisesRegex(ValueError, "date normalization"):
                migration.check_library()


class ImportSafetyTests(unittest.TestCase):
    """Verify replacement fails closed using simulated backends."""

    @staticmethod
    def importer():
        """Load the standalone importer without connecting to any service."""
        with mock.patch.object(
            sys, "path", [str(Path(__file__).resolve().parents[1] / "tools"), *sys.path]
        ):
            return importlib.import_module("tools.reimport_port_dump")

    def test_failed_import_does_not_swap(self):
        """An incomplete temporary index never replaces the live index."""
        importer = self.importer()
        with mock.patch.multiple(
            importer,
            build_out_meili_index=mock.Mock(
                return_value=("test", "plum", mock.Mock(), mock.Mock())
            ),
            target_index_metadata=mock.Mock(return_value=("id", {})),
            create_import_index=mock.Mock(return_value=("temporary", mock.Mock())),
            import_meili_documents_to_index=mock.Mock(return_value=(2, 1, 1)),
            cleanup_import_index=mock.Mock(),
            swap_import_index=mock.Mock(),
        ):
            with self.assertRaises(SystemExit):
                importer.replace_meili_from_dump(
                    Path("unused"), 10, 2, 1000, 1, 1, "swap"
                )
            importer.swap_import_index.assert_not_called()
            importer.cleanup_import_index.assert_called_once()

    def test_prepared_dump_import_round_trip(self):
        """Importer reads new IDs and merged companions, omitting audit files."""
        importer = self.importer()
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / "source", Path(root) / "output"
            source.mkdir()
            for uid, observed in (("old-a", 100), ("old-b", 200)):
                doc = {
                    "id": uid,
                    "ip": "192.0.2.1",
                    "body": {
                        "endtime": observed,
                        "ports": [{"portid": "80", "scripts": []}],
                    },
                }
                (source / f"{uid}.json").write_text(json.dumps(doc))
                (source / f"{uid}.time").write_text(
                    json.dumps({"first_seen": observed, "last_seen": observed})
                )
            with mock.patch.object(migration, "check_library", return_value="test"):
                migration.prepare(source, output)
            docs = list(importer.iter_documents(importer.iter_json_files(output)))
            self.assertEqual(len(docs), 1)
            doc, error = docs[0]
            self.assertIsNone(error)
            self.assertNotIn(doc["id"], ("old-a", "old-b"))
            normalizer = SimpleNamespace(
                normalize_seen_range=lambda first, last: (
                    migration.timestamp(first),
                    migration.timestamp(last),
                )
            )
            with mock.patch.object(
                importer.index_kvrocks, "KVrocksIndexer", normalizer
            ):
                self.assertEqual(
                    importer.load_time_snapshot(output), {doc["id"]: (100, 200)}
                )

    def test_incomplete_kvrocks_rebuild_fails(self):
        """Partial indexing must not return a successful migration status."""
        importer = self.importer()
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "doc.json").write_text("{}")
            with mock.patch.multiple(
                importer,
                load_tool_config=mock.Mock(return_value=10),
                validate_out_targets=mock.Mock(),
                print_out_targets=mock.Mock(),
                prepare_index_kvrocks_runtime=mock.Mock(),
                rebuild_kvrocks_from_dump=mock.Mock(return_value=(1, 0, 1)),
            ):
                with self.assertRaisesRegex(SystemExit, "Incomplete Kvrocks"):
                    importer.main(
                        ["--input-dir", root, "--skip-meili", "--areyousure_yes"]
                    )


if __name__ == "__main__":
    unittest.main()
