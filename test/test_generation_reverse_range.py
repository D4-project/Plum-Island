"""Newest-first filtered reads must pass through the generation adapter."""

import unittest
from unittest.mock import Mock

from app.utils.index_generations import GenerationClient, generation_prefix


class GenerationReverseRangeTest(unittest.TestCase):
    def test_reverse_range_routes_legacy_and_managed_reads(self):
        """Preserve score bounds and pagination in direct and pipeline calls."""
        for generation in ("", "a" * 32):
            for pipelined in (False, True):
                with self.subTest(generation=generation, pipelined=pipelined):
                    raw = Mock()
                    raw.get.return_value = "-"
                    ownership = Mock()
                    ownership.execute.return_value = [True]
                    reader = Mock()
                    reader.execute.return_value = [[("uid", 150.0)]]
                    raw.pipeline.side_effect = (
                        [ownership, reader] if generation else [reader]
                    )
                    client = GenerationClient(raw, generation)
                    target = client.pipeline() if pipelined else client
                    result = target.zrevrangebyscore(
                        "last_seen_index", 200, 100,
                        start=2, num=64, withscores=True,
                    )
                    if pipelined:
                        result = target.execute()[0]
                    self.assertEqual(result, [("uid", 150.0)])
                    reader.zrevrangebyscore.assert_called_once_with(
                        generation_prefix(generation) + "last_seen_index",
                        200, 100, start=2, num=64, withscores=True,
                    )


if __name__ == "__main__":
    unittest.main()
