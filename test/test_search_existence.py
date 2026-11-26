"""Regression tests for the single-result historical search probe."""

import unittest
from unittest.mock import Mock

from app.utils.kvrocks import KVrocksIndexer
from app.utils.search_existence import has_observation, matching_observations
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
