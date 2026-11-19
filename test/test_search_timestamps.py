"""Scoped timestamp equivalence and bounded replies without full IP histories."""

import copy
import unittest
from unittest.mock import patch

from test.test_kvrocks_search import make_indexer
from search_timestamps import search_timestamps


class SearchTimestampsTest(unittest.TestCase):
    """Preserve membership, missing fields, normalized bounds and empty scopes."""

    def test_membership_and_timestamp_normalization(self):
        """Omit unrelated/orphan metadata while retaining missing-doc bounds."""
        indexer = make_indexer({"ip:8.8.8.8": {"one", "two", "missing", "unselected"}})
        indexer.r.hashes = {
            "doc:one": {"first_seen": "200", "last_seen": "100", "extra": "unused"},
            "doc:two": {"first_seen": "invalid", "last_seen": "300"},
            "doc:orphan": {"first_seen": "1", "last_seen": "999"},
            "doc:unselected": {"first_seen": "1", "last_seen": "999"},
        }
        selected = {
            "8.8.8.8": ["one", "two", "one", "missing", "orphan"],
            "9.9.9.9": [],
        }
        before = copy.deepcopy(selected)
        self.assertEqual(
            search_timestamps(indexer, selected, batch_size=2),
            {
                "8.8.8.8": {
                    "one": {"first_seen": 100, "last_seen": 200},
                    "two": {"first_seen": 300, "last_seen": 300},
                    "missing": {"first_seen": None, "last_seen": None},
                    "min_seen": 100,
                    "max_seen": 300,
                },
                "9.9.9.9": {"min_seen": None, "max_seen": None},
            },
        )
        self.assertEqual(selected, before)
        metadata = [
            command
            for _, batch in indexer.r.batches
            for command in batch
            if command[0] == "fields"
        ]
        self.assertEqual(
            {command[1] for command in metadata}, {"doc:one", "doc:two", "doc:missing"}
        )
        self.assertTrue(
            all(command[2:] == ("first_seen", "last_seen") for command in metadata)
        )
        self.assertFalse(indexer.r.direct_reads)

    def test_batch_boundaries_and_duplicate_membership(self):
        """Bound replies around empty, full and overflowing scalar batches."""
        for count in (0, 1, 249, 250, 251, 500, 501, 1001):
            with self.subTest(count=count):
                uids = [f"uid-{number}" for number in range(count)]
                indexer = make_indexer({"ip:8.8.8.8": set(uids)})
                for uid in uids:
                    indexer.r.hashes[f"doc:{uid}"] = {"first_seen": 10, "last_seen": 20}
                actual = search_timestamps(indexer, {"8.8.8.8": uids})
                self.assertEqual(
                    set(actual["8.8.8.8"]), {*uids, "min_seen", "max_seen"}
                )
                self.assertTrue(
                    all(len(batch) <= 250 for _, batch in indexer.r.batches)
                )
                self.assertEqual(len(indexer.r.batches), 2 * ((count + 249) // 250))

    def test_backend_error_does_not_return_partial_metadata(self):
        """An unavailable backend remains an error rather than a partial result."""
        indexer = make_indexer({"ip:8.8.8.8": {"one"}})
        with patch.object(
            indexer.r, "pipeline", side_effect=RuntimeError("unavailable")
        ):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                search_timestamps(indexer, {"8.8.8.8": ["one"]})

    def test_partial_reversed_and_date_formats_match_history(self):
        """Keep legacy normalization across formats and missing field values."""
        cases = {
            "missing": {},
            "invalid": {"first_seen": "invalid", "last_seen": -1},
            "first": {"first_seen": "100"},
            "last": {"last_seen": "200"},
            "reversed": {"first_seen": 300, "last_seen": 100},
            "formats": {
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": 1767225601000,
            },
        }
        indexer = make_indexer({"ip:8.8.8.8": set(cases)})
        indexer.r.hashes = {f"doc:{uid}": fields for uid, fields in cases.items()}
        for uid in cases:
            with self.subTest(uid=uid):
                self.assertEqual(
                    search_timestamps(indexer, {"8.8.8.8": [uid]})["8.8.8.8"],
                    indexer.get_timestamp_for_ip("8.8.8.8", {uid}),
                )


if __name__ == "__main__":
    unittest.main()
