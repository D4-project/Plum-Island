#!/usr/bin/env python3
"""Tests for missing Meilisearch document recovery tooling."""

# pylint: disable=consider-using-with

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock
import tempfile

from tools import reintegrate_missing_meili as repair


class MissingMeiliRepairTest(TestCase):
    """Exercise consistency comparison and raw source recovery."""

    def setUp(self):
        """Create isolated work storage."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.connection, self.work_path, _temporary = repair.create_work_database(
            self.temp_path / "work.sqlite"
        )

    def tearDown(self):
        """Close isolated work storage."""
        self.connection.close()
        self.temp_dir.cleanup()

    def test_present_meili_uids_are_removed_from_candidates(self):
        """Only Kvrocks-only UIDs remain after Meilisearch streaming."""
        self.connection.executemany(
            "INSERT INTO candidates(uid) VALUES (?)",
            [("present",), ("missing",)],
        )
        self.connection.commit()
        index = mock.Mock()
        index.get_documents.side_effect = [
            SimpleNamespace(
                results=[SimpleNamespace(id="present")],
                total=1,
            ),
            SimpleNamespace(results=[], total=1),
        ]

        processed = repair.remove_present_meili_uids(index, self.connection, 100)

        remaining = self.connection.execute(
            "SELECT uid FROM candidates ORDER BY uid"
        ).fetchall()
        self.assertEqual(processed, 1)
        self.assertEqual(remaining, [("missing",)])

    def test_raw_recovery_keeps_newest_matching_document(self):
        """Repeated UID observations recover newest raw body."""
        old_result = {
            "addr": "213.186.33.4",
            "endtime": 100,
            "ports": [{"portid": "80", "protocol": "tcp", "state": "open"}],
        }
        new_result = dict(old_result, endtime=200)
        expected_document = repair.split_raw_scan_result(old_result)[0]
        uid = expected_document["id"]
        self.connection.execute(
            "INSERT INTO candidates(uid, ip) VALUES (?, ?)",
            (uid, old_result["addr"]),
        )
        self.connection.commit()

        json_folder = self.temp_path / "jsons"
        json_folder.mkdir()
        with open(json_folder / "old.json", "w", encoding="utf-8") as json_handle:
            json.dump(old_result, json_handle)
        with open(json_folder / "new.json", "w", encoding="utf-8") as json_handle:
            json.dump(new_result, json_handle)

        summary = repair.recover_candidates_from_json(
            json_folder,
            {old_result["addr"]: {uid}},
            self.connection,
            progress_every=0,
        )

        recovered_json = self.connection.execute(
            "SELECT document_json FROM candidates WHERE uid = ?",
            (uid,),
        ).fetchone()[0]
        recovered = json.loads(recovered_json)
        self.assertEqual(summary["recovered"], 1)
        self.assertEqual(summary["matched_occurrences"], 2)
        self.assertEqual(recovered["body"]["endtime"], 200)
        self.assertEqual(recovered["body"]["ports"][0]["portid"], "80")

    def test_failed_reintegration_task_is_rejected(self):
        """A terminal failed Meilisearch task cannot count as repaired."""
        index = mock.Mock()
        index.wait_for_task.return_value = SimpleNamespace(
            status="failed",
            error={"message": "invalid document"},
        )

        with self.assertRaisesRegex(repair.ReintegrationError, "status failed"):
            repair.wait_for_success(
                index,
                SimpleNamespace(task_uid=99),
                timeout_ms=5000,
            )

    def test_report_marks_recoverable_and_unrecoverable_uids(self):
        """Dry-run report separates recoverable sources from data loss."""
        self.connection.executemany(
            "INSERT INTO candidates(uid, document_json) VALUES (?, ?)",
            [("recoverable", "{}"), ("lost", None)],
        )
        self.connection.commit()
        report_path = self.temp_path / "report.csv"

        _path, counts = repair.write_report(
            report_path,
            self.connection,
            applied=False,
        )

        self.assertEqual(
            counts,
            {"reintegrated": 0, "recoverable": 1, "unrecoverable": 1},
        )
        self.assertIn("recoverable,recoverable", report_path.read_text("utf-8"))


if __name__ == "__main__":
    import unittest

    unittest.main()
