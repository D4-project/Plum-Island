"""Bounded protocol backfill should update only missing protocol indexes."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

from tools.backfill_port_protocol import backfill


class BackfillPortProtocolTest(TestCase):
    """Check selective backfill without external services."""

    def test_reads_missing_uids_and_updates_protocol_only(self):
        """Existing indexes stay untouched; Meili lookup uses pending IDs."""
        indexer = MagicMock()
        indexer.r.sscan_iter.return_value = iter(("missing", "existing"))
        indexer.r.pipeline.return_value.execute.return_value = [0, 1]
        index = MagicMock()
        index.get_documents.return_value = SimpleNamespace(
            results=[
                {
                    "id": "missing",
                    "body": {"ports": [{"portid": 53, "protocol": "udp"}]},
                }
            ]
        )

        self.assertEqual(backfill(indexer, index, 2), (2, 1, 0))
        index.get_documents.assert_called_once_with(
            {"ids": ["missing"], "fields": ["id", "body.ports"], "limit": 1}
        )
        indexer.replace_field_values_batch.assert_called_once_with(
            "port_protocol", [{"uid": "missing", "port_protocol": ["udp/53"]}]
        )
