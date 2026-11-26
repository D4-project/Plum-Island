"""Verify capture retention and its write barriers against disposable data."""

from contextlib import closing, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from test.test_reimport_history import MemoryStore
from tools import purge


class PurgeStore(MemoryStore):
    """Supply the sorted-set and journal operations used by retention."""

    def zrangebyscore(self, key, minimum, maximum, **limits):
        """Return the configured batch in timestamp order."""
        if minimum != 0 or not maximum.startswith("("):
            raise AssertionError((minimum, maximum))
        scores = self.data.get(key, {})
        cutoff = int(maximum[1:])
        start = limits["start"]
        candidates = sorted(
            (score, uid) for uid, score in scores.items() if minimum <= score < cutoff
        )
        return [uid for _, uid in candidates[start : start + limits["num"]]]

    def zrem(self, key, uid):
        """Remove a document from a timestamp index."""
        self.data.get(key, {}).pop(uid, None)

    def scard(self, key):
        """Count the remaining documents of an IP."""
        return len(self.smembers(key))

    def rpush(self, key, value):
        """Record a reconciliation journal entry."""
        self.data.setdefault(key, []).append(value)


class PurgeTest(TestCase):
    """Keep both indexes consistent across retention and retry."""

    def setUp(self):
        # Let unittest retain this directory until all fixture cleanup finishes.
        # pylint: disable-next=consider-using-with
        directory = self.enterContext(TemporaryDirectory())
        self.directory = Path(directory)
        self.enterContext(patch.dict(os.environ, PLUM_INDEX_STATE_DIR=directory))
        self.enterContext(redirect_stdout(StringIO()))
        self.raw = PurgeStore()
        self.raw.data = {
            "last_seen_index": {"old": 99, "edge": 100, "fresh": 101},
            "first_seen_index": {"old": 10, "edge": 10, "fresh": 10},
            "all_uids": {"old", "edge", "fresh", "undated"},
            "doc:old": {"ip": "93.184.216.34", "last_seen": "99"},
            "uid:old": "93.184.216.34",
            "tags:old": {"proto:rdp"},
            "tag:proto:rdp": {"old", "fresh"},
            "ip:93.184.216.34": {"old"},
            "net:93.184.216.0/24": {"old"},
            "all_ips": {"93.184.216.34", "93.184.216.35"},
            "coverage:old": "coverage",
            "contributions:old": '{"rdp-rule":["proto:rdp"]}',
            "rule_matches:rdp-rule": {"old", "fresh"},
            "rule_drift": {"old"},
            purge.CONTROL + "job": '{"id":"staged","phase":"reparsing"}',
        }
        self.meili = Mock()
        self.meili.delete_documents.return_value = SimpleNamespace(task_uid=42)
        self.meili.wait_for_task.return_value = SimpleNamespace(status="succeeded")

    def test_strict_cutoff_and_complete_removal(self):
        """Keep boundary/fresh/undated records and journal matching old records."""
        self.assertEqual(purge.purge_documents(self.raw, self.meili, 100), 1)
        self.meili.delete_documents.assert_called_once_with(["old"])
        self.meili.wait_for_task.assert_called_once_with(
            42, timeout_in_ms=60_000, interval_in_ms=500
        )
        data = self.raw.data
        self.assertEqual(data["all_uids"], {"edge", "fresh", "undated"})
        self.assertEqual(data["tag:proto:rdp"], {"fresh"})
        self.assertEqual(data["rule_matches:rdp-rule"], {"fresh"})
        self.assertEqual(data["rule_drift"], set())
        self.assertEqual(data["all_ips"], {"93.184.216.35"})
        self.assertFalse(data["ip:93.184.216.34"])
        self.assertFalse(data["net:93.184.216.0/24"])
        self.assertEqual(data["last_seen_index"], {"edge": 100, "fresh": 101})
        self.assertNotIn("old", data["first_seen_index"])
        for key in ("doc", "uid", "tags", "coverage", "contributions"):
            self.assertNotIn(f"{key}:old", data)
        self.assertEqual(data[purge.CONTROL + "deleted:staged"], {"old"})
        journal = data[purge.CONTROL + "journal:staged"]
        self.assertEqual([json.loads(entry)["delete"] for entry in journal], ["old"])
        self.assertEqual(purge.purge_documents(self.raw, self.meili, 100), 0)

    def test_failed_meili_task_keeps_kvrocks(self):
        """Leave the retry candidates and their memberships intact on failure."""
        before = deepcopy(self.raw.data)
        self.meili.wait_for_task.return_value.status = "failed"
        with self.assertRaisesRegex(purge.PurgeError, "task 42 did not succeed"):
            purge.purge_documents(self.raw, self.meili, 100)
        self.assertEqual(self.raw.data, before)
        self.meili.wait_for_task.return_value.status = "succeeded"
        self.assertEqual(purge.purge_documents(self.raw, self.meili, 100), 1)

    def test_pending_exports_refuse_purge(self):
        """Check finished, unexported jobs even after the Meili write succeeds."""
        database = self.directory / "jobs.db"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE jobs (finished BOOLEAN, exported BOOLEAN)")
            connection.executemany(
                "INSERT INTO jobs VALUES (?, ?)", [(True, True), (False, False)]
            )
            connection.commit()
            uri = f"sqlite:///{database}"
            self.assertFalse(purge.has_pending_exports(uri))
            connection.execute("INSERT INTO jobs VALUES (TRUE, FALSE)")
            connection.commit()
            self.assertTrue(purge.has_pending_exports(uri))
        with self.assertRaisesRegex(purge.PurgeError, "Finish exporting"):
            purge.require_idle_exports(
                Mock(zcount=Mock(return_value=0)), self.meili, uri
            )
        self.meili.get_tasks.assert_not_called()

    def test_confirmation_is_exact_and_keep_is_positive(self):
        """Reject destructive execution with a missing or abbreviated flag."""
        for args in (
            ["--keep", "30d"],
            ["--yes-delete", "--keep", "30d"],
            ["--yes-delete-data", "--keep", "0d"],
            ["--yes-delete-data", "--keep", "30"],
        ):
            with self.subTest(args=args), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as error:
                    purge.main(args)
                self.assertEqual(error.exception.code, 2)
        self.assertEqual(
            purge.parse_args(["--yes-delete-data", "--keep", "30d"]).keep, 30
        )

    def test_cli_uses_yaml_out_backends_and_index(self):
        """Use the OUT pair and credentials even when the IN pair is present."""
        settings = {
            "IN_MEILI_URL": "http://in.example",
            "IN_MEILI_API_KEY": "test-in",
            "IN_KVROCKS_HOST": "in.example",
            "IN_KVROCKS_PORT": 6666,
            "OUT_MEILI_URL": "http://out.example",
            "OUT_MEILI_API_KEY": "test-out",
            "OUT_KVROCKS_HOST": "out.example",
            "OUT_KVROCKS_PORT": 6667,
            "INDEX_NAME": "output-index",
        }
        with (
            patch.object(purge, "load_yaml_config", return_value=settings) as load,
            patch.object(purge, "KVrocksIndexer") as kvrocks,
            patch.object(purge, "Client") as meili,
            patch.object(purge, "require_idle_exports") as idle,
            patch.object(purge, "purge_documents", return_value=0) as delete,
        ):
            raw = kvrocks.return_value.raw
            raw.mget.return_value = [None, None, None]
            self.assertEqual(purge.main(["--yes-delete-data", "--keep", "90d"]), 0)
        load.assert_called_once_with(purge.CONFIG_PATH)
        kvrocks.assert_called_once_with("out.example", 6667, socket_timeout=30)
        meili.assert_called_once_with("http://out.example", "test-out", timeout=30)
        meili.return_value.index.assert_called_once_with("output-index")
        index = meili.return_value.index.return_value
        idle.assert_called_once_with(raw, index, None)
        self.assertEqual(delete.call_args.args[:2], (raw, index))

    def test_missing_out_never_uses_in(self):
        """Fail before opening an index when only input endpoints are configured."""
        settings = {
            "IN_MEILI_URL": "http://in.example",
            "IN_KVROCKS_HOST": "in.example",
            "IN_KVROCKS_PORT": 6666,
        }
        with (
            patch.object(purge, "KVrocksIndexer") as kvrocks,
            patch.object(purge, "Client") as meili,
        ):
            with self.assertRaisesRegex(purge.PurgeError, "Missing OUT_MEILI_URL"):
                purge.open_out_backends(settings)
        kvrocks.assert_not_called()
        meili.assert_not_called()
