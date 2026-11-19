"""Observed tag producer/consumer lifecycle without external services."""

import unittest
from unittest.mock import patch

from test.test_reimport_history import MemoryStore, rebuild
from kvrocks import KVrocksIndexer
from tools.tag_mgmt import flush_existing_tag_indexes


class CatalogueStore(MemoryStore):
    """Record read cost and add counts to the existing in-memory index fixture."""

    def __init__(self):
        super().__init__()
        self.scans = []
        self.memberships = []
        self.counts = []

    def smembers(self, key):
        """Record membership reads to detect expensive catalogue regressions."""
        self.memberships.append(key)
        return super().smembers(key)

    def scard(self, key):
        """Read cardinality without materializing document memberships."""
        self.counts.append(key)
        return len(self.data.get(key, set()))

    def scan_iter(self, match, **kwargs):
        """Record maintenance-only keyspace scans."""
        self.scans.append(match)
        return super().scan_iter(match, **kwargs)


class ObservedTagsTest(unittest.TestCase):
    """Keep ingestion, retagging, maintenance and catalogue reads consistent."""

    def setUp(self):
        """Use the real indexer with disposable command semantics."""
        self.indexer = KVrocksIndexer.__new__(KVrocksIndexer)
        self.store = self.indexer.r = CatalogueStore()

    def test_ingestion_retries_and_retagging_keep_only_live_tags(self):
        """Idempotent candidates reflect current reverse indexes after removals."""
        doc = {"uid": "u", "ip": "8.8.8.8", "tag": ["proto:ssh", "vendor:old"]}
        self.indexer.add_documents_batch([doc, doc])
        self.assertEqual(self.indexer.get_observed_tags(), ["proto:ssh", "vendor:old"])
        self.indexer.replace_field_values_batch(
            "tag", [{"uid": "u", "tag": ["product:new", "product:new"]}]
        )
        self.assertEqual(self.indexer.get_observed_tags(), ["product:new"])
        self.assertEqual(self.store.scard("tag:product:new"), 1)
        self.indexer.replace_field_values_batch("tag", [{"uid": "u", "tag": []}])
        self.assertEqual(self.indexer.get_observed_tags(), [])
        # Ghost candidates are deliberately retained to avoid pruning/write races.
        self.assertIn("product:new", self.store.data["tag_catalogue"])

    def test_preserved_tags_and_other_fields_do_not_change_catalogue(self):
        """A normal rebuild without retagging must preserve existing tag data."""
        self.indexer.replace_field_values_batch(
            "tag", [{"uid": "u", "tag": ["proto:ssh"]}]
        )
        self.indexer.add_documents_batch(
            [{"uid": "u", "ip": "8.8.8.8", "tag": ["proto:http"]}], include_tags=False
        )
        self.indexer.replace_field_values_batch("port", [{"uid": "u", "port": ["443"]}])
        self.assertEqual(self.indexer.get_observed_tags(), ["proto:ssh"])

    def test_read_cost_depends_on_tags_not_documents(self):
        """No keyspace scan or UID membership read is used by the catalogue."""
        self.store.data["tag_catalogue"] = {f"product:p{n}" for n in range(1001)}
        self.store.data["tag:product:p7"] = {str(n) for n in range(10000)}
        self.assertEqual(self.indexer.get_observed_tags(), ["product:p7"])
        self.assertEqual(self.store.memberships, ["tag_catalogue"])
        self.assertEqual(len(self.store.counts), 1001)
        self.assertEqual(self.store.scans, [])

    def test_backfill_seeds_existing_data_and_preserves_concurrent_candidates(self):
        """Maintenance is repeatable, reads counts only, and never clears writers."""
        self.store.data.update(
            {
                "tag:proto:ssh": {"u"},
                "tag:product:a": {"u"},
                "tag:vendor:empty": set(),
                "tags:u": {"proto:ssh"},
                "tag_catalogue": {"product:concurrent"},
            }
        )
        self.assertEqual(self.indexer.backfill_tag_catalogue(batch_size=1), 3)
        self.indexer.backfill_tag_catalogue(batch_size=2)
        self.assertEqual(self.indexer.get_observed_tags(), ["product:a", "proto:ssh"])
        self.assertIn("product:concurrent", self.store.data["tag_catalogue"])
        self.assertEqual(self.store.scans, ["tag:*", "tag:*"])
        self.assertEqual(self.store.memberships, ["tag_catalogue"])

    def test_rebuild_cleanup_tracks_tag_preservation(self):
        """Only rebuilds removing tag indexes clear their candidate catalogue."""
        self.store.data["tag_catalogue"] = {"proto:ssh"}
        rebuild.rebuild_kvrocks(self.indexer)
        self.assertIn("tag_catalogue", self.store.data)
        rebuild.rebuild_kvrocks(self.indexer, include_tags=True)
        self.assertNotIn("tag_catalogue", self.store.data)
        self.store.data["tag_catalogue"] = {"proto:ssh"}
        rebuild.clean_tag_indexes(self.indexer)
        self.assertNotIn("tag_catalogue", self.store.data)
        self.store.data["tag_catalogue"] = {"proto:ssh"}
        with patch("builtins.print"):
            flush_existing_tag_indexes(self.indexer, 100)
        self.assertNotIn("tag_catalogue", self.store.data)
