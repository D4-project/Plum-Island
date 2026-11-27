"""Regression tests for the single-result historical search probe."""

import unittest
from unittest.mock import Mock

from app.utils.kvrocks import KVrocksIndexer
from app.utils.search_existence import (
    chronological_observation_batches,
    has_observation,
    matching_observations,
)
from app.views import KVSearchView


class SearchExistenceTest(unittest.TestCase):
    """Use the production parser with small deterministic index replies."""

    def setUp(self):
        self.indexer = KVrocksIndexer.__new__(KVrocksIndexer)
        self.client = self.indexer.r = Mock()

    def probe(self, query):
        """Compile the same criteria as the GUI before probing."""
        criteria, valid, error = KVSearchView().parse_query(query)
        self.assertTrue(valid, error)
        return has_observation(self.indexer, criteria, 10, 20)

    def test_stops_before_reading_next_scan_page(self):
        """One match on a nonterminal Redis cursor ends the lookup."""
        self.client.sscan.return_value = (91, ["old", "recent"])
        metadata, matching = Mock(), Mock()
        metadata.execute.return_value = ["192.0.2.1", 9, "192.0.2.2", 11]
        matching.execute.return_value = [True, False]
        self.client.pipeline.side_effect = [metadata, matching]
        self.assertTrue(self.probe("tag:vendor:nginx AND NOT tag:vendor:apache"))
        self.client.sscan.assert_called_once()
        self.client.zrangebyscore.assert_not_called()

    def test_full_iterator_yields_each_matching_uid_from_the_page(self):
        """Background consumers can continue after the first matching capture."""
        self.client.sscan.return_value = (0, ["first", "excluded", "second"])
        metadata, matching = Mock(), Mock()
        metadata.execute.return_value = [
            "192.0.2.1",
            11,
            "192.0.2.2",
            12,
            "192.0.2.3",
            13,
        ]
        matching.execute.return_value = [True, False, True, True, True, False]
        self.client.pipeline.side_effect = [metadata, matching]
        criteria, valid, error = KVSearchView().parse_query(
            "tag:vendor:nginx AND NOT tag:vendor:apache"
        )
        self.assertTrue(valid, error)
        self.assertEqual(
            list(matching_observations(self.indexer, criteria, 10, 20)),
            ["first", "second"],
        )

    def test_modifier_only_search_uses_small_timestamp_pages(self):
        """Missing or stale records cannot satisfy a partial header predicate."""
        self.client.zrangebyscore.side_effect = [[("missing", 10), ("present", 20)], []]
        metadata, matching = Mock(), Mock()
        metadata.execute.return_value = [None, 10, "192.0.2.2", 20]
        matching.execute.return_value = [{"location:nginx", "server:apache"}]
        self.client.pipeline.side_effect = [metadata, matching]
        self.assertFalse(self.probe("http_headval:server.lk:nginx"))
        self.assertEqual(self.client.zrangebyscore.call_count, 2)
        self.client.sscan.assert_not_called()

    def test_filtered_scan_reads_frozen_window_newest_first_and_resumes(self):
        """Filtered collection never scans tag history outside its since window."""
        self.client.zrevrangebyscore.side_effect = [
            [("new", 20), ("same-a", 15), ("same-b", 15)],
            [],
        ]
        metadata, matching = Mock(), Mock()
        metadata.execute.return_value = [
            "192.0.2.1",
            20,
            "192.0.2.2",
            15,
            "192.0.2.3",
            15,
        ]
        matching.execute.return_value = [True, True, True]
        self.client.pipeline.side_effect = [metadata, matching]
        criteria, valid, error = KVSearchView().parse_query("tag:vendor:nginx")
        self.assertTrue(valid, error)
        pages = list(
            chronological_observation_batches(
                self.indexer, criteria, 10, 20, resume=(20, 0)
            )
        )
        self.assertEqual(pages[0][2], (15, 2))
        self.client.zrevrangebyscore.assert_any_call(
            "last_seen_index", 20, 10, start=0, num=64, withscores=True
        )
        self.client.zrevrangebyscore.assert_any_call(
            "last_seen_index", 15, 10, start=2, num=64, withscores=True
        )
        self.client.sscan.assert_not_called()
