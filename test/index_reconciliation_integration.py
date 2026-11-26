"""Explicit integration checks against a disposable Unix-socket Redis server.

This is not production Kvrocks performance validation. Start a dedicated test
server at /tmp/plum-271-test.sock; database 15 is cleared before each test.
Never point this suite at an application backend. Run with isolated Flask SQL
configuration as described in the reconciliation operational documentation.
"""

from copy import deepcopy
import json
import os
import multiprocessing
import time
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from test.test_tag_reconciliation import snapshot

import redis
from meilisearch.errors import MeilisearchApiError
from meilisearch.models.document import Document
from requests import Response

from app.utils.index_generations import (
    ACTIVE,
    CONTROL,
    GenerationClient,
    generation_prefix,
    read_json,
    write_json,
)
from app.utils.index_reconciliation import (
    ReconciliationWorker,
    SnapshotInvalid,
    index_for,
    ingest_sources,
    ingest_indexer_sources,
    queue_snapshot,
    delete_capture,
    reconciliation_status,
)
from app.utils.index_activity import (
    ACTIVITY,
    PACING,
    SAMPLES,
    ActivityMonitor,
    pacing_status,
)
from app.utils.index_pacing import PacedReconciliationWorker
from app.utils.index_source_recovery import (
    MISSING_SOURCES,
    SOURCE_CONFLICT,
    requeue_orphan_exclusion,
)
from app.utils.index_supervisor import IndexSupervisor
from app.utils.search_timestamps import search_timestamps

from tools.index_generation_admin import retired_keys
from tools.reconcile_index import install_stop_handlers


def source(uid="one", port="443", endtime="2026-09-10T00:00:00"):
    """Small real parser input with stable UID and timestamps."""
    return {
        "id": uid,
        "ip": "93.184.216.34",
        "body": {
            "endtime": endtime,
            "hostnames": [],
            "ports": [{"portid": port, "protocol": "tcp", "scripts": []}],
        },
    }


class ReconciliationCase(unittest.TestCase):
    """Isolated backend and source fixtures shared by protocol integration checks."""

    def setUp(self):
        """Setup."""
        self.raw = redis.Redis(
            unix_socket_path="/tmp/plum-271-test.sock",
            db=15,
            decode_responses=True,
            protocol=2,
        )
        self.raw.flushdb()
        directory = self.enterContext(
            tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
                prefix="plum-271-locks-"
            )  # pylint: disable=consider-using-with
        )
        self.enterContext(patch.dict(os.environ, {"PLUM_INDEX_STATE_DIR": directory}))
        self.documents = {"one": source()}
        self.meili = Mock()
        self.meili.get_document.side_effect = lambda uid: Document(
            deepcopy(self.documents[uid])
        )
        self.meili.get_documents.side_effect = self.source_page
        self.first = snapshot([("a", "port:443", ["proto:https"])])
        # Existing legacy index has accumulated history absent from Meilisearch.
        index_for(GenerationClient(self.raw, "", writable=True)).add_documents_batch(
            [
                {
                    "uid": "one",
                    "ip": "93.184.216.34",
                    "port": ["443"],
                    "first_seen": 100,
                    "last_seen": 200,
                    "tag": ["type:server"],
                }
            ]
        )

    def source_page(self, query):
        """Model both batches by primary key and paginated inventory."""
        if "ids" in query:
            return SimpleNamespace(
                results=[
                    Document(deepcopy(self.documents[uid]))
                    for uid in reversed(query["ids"])
                    if uid in self.documents
                ]
            )
        ids = sorted(self.documents)[query["offset"] : query["offset"] + query["limit"]]
        return SimpleNamespace(results=[Document({"id": uid}) for uid in ids])

    def worker(self):
        """Worker."""
        return ReconciliationWorker(self.raw, self.meili, batch_size=1, pause_seconds=0)

    def scan(self, worker):
        """Finish the bounded planning/scanning phases without publishing."""
        while not worker.job["candidates_ready"]:
            worker.prepare_candidates_batch()
        while worker.job["pending_uids"] or not worker.job["scan_complete"]:
            worker.scan_batch()

    def publish(self, state):
        """Publish."""
        queue_snapshot(self.raw, state)
        self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")


class GenerationCopyIntegrationTest(ReconciliationCase):
    """Empty fields survive copying across imports, ingestion and recovery."""

    def test_initial_import_with_empty_fields(self):
        """Legacy import and first managed import accept captures without banners."""
        legacy = index_for(GenerationClient(self.raw, "", writable=True))
        legacy.add_documents_batch(
            [{"uid": "empty", "ip": "1.1.1.1", "banner": [], "port": ["22"]}]
        )
        self.documents["empty"] = dict(source("empty", "22"), ip="1.1.1.1")
        self.assertFalse(legacy.r.exists("banners:empty"))
        self.publish(self.first)
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("all_uids"), {"one", "empty"})
        self.assertEqual(current.smembers("ports:empty"), {"22"})
        self.assertFalse(current.exists("banners:empty"))

    def test_parser_update_reimports_empty_fields_into_incremental_generation(self):
        """A parent tombstone is normal, including during full document reparsing."""
        self.publish(self.first)
        parent = GenerationClient(self.raw, self.raw.get(ACTIVE))
        self.assertFalse(parent.exists("banners:one"))
        changed = snapshot([("a", "port:443", ["proto:https"])], {"server": True})
        self.publish(changed)
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("ports:one"), {"443"})
        self.assertFalse(current.exists("banners:one"))
        self.assertEqual(current.hget("doc:one", "first_seen"), "100")
        self.assertFalse(parent.exists("banners:one"))

    def test_ingestion_before_during_and_after_incremental_reparse(self):
        """The scheduler's shared writer handles empty fields and journal replay."""
        queue_snapshot(self.raw, self.first)
        indexer = SimpleNamespace(raw=self.raw, accepts_source_documents=True)
        self.assertTrue(ingest_indexer_sources(indexer, [source("early")]))
        self.documents["early"] = source("early")
        self.worker().run()
        parent = GenerationClient(self.raw, self.raw.get(ACTIVE))
        changed = snapshot([("a", "port:443", ["type:server"])], {"server": True})
        queue_snapshot(self.raw, changed)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        self.assertTrue(ingest_indexer_sources(indexer, [source("during")]))
        self.assertEqual(parent.smembers("tags:during"), {"type:server"})
        while not worker.replay_batch():
            pass
        self.assertTrue(ingest_indexer_sources(indexer, [source("after")]))
        # Existing capture inherits an absent field from the retained parent.
        self.assertTrue(ingest_indexer_sources(indexer, [source("during", "22")]))
        current = GenerationClient(self.raw)
        self.assertEqual(
            current.smembers("all_uids"), {"one", "early", "during", "after"}
        )
        self.assertEqual(current.smembers("ports:during"), {"22"})
        self.assertEqual(parent.smembers("ports:during"), {"443"})
        self.assertFalse(current.exists("banners:during"))

    def test_new_rules_survive_publishing_an_older_revision_and_revert(self):
        """Live ingest may lead a frozen job and remains reconcilable after a revert."""
        self.publish(self.first)
        frozen = snapshot([("a", "port:443", ["type:server"])])
        saved = snapshot([("a", "port:443", ["proto:tls"])])
        queue_snapshot(self.raw, frozen)
        worker = self.worker()
        self.assertTrue(worker.start())
        self.scan(worker)
        indexer = SimpleNamespace(raw=self.raw, accepts_source_documents=True)
        incoming = source("recent")
        self.documents["recent"] = incoming
        self.assertTrue(
            ingest_indexer_sources(indexer, [incoming], live_snapshot=saved)
        )
        old = GenerationClient(self.raw)
        self.assertEqual(old.smembers("tags:recent"), {"proto:tls"})
        self.assertEqual(old.smembers("tags:one"), {"proto:https"})
        while not worker.replay_batch():
            pass
        active = GenerationClient(self.raw)
        self.assertEqual(active.smembers("tags:recent"), {"proto:tls"})
        self.assertEqual(active.smembers("tags:one"), {"type:server"})

        # Saving the just-published rule again leaves matching desired and
        # published snapshots, but the later live contributions still need repair.
        self.assertEqual(reconciliation_status(self.raw)["phase"], "queued")
        self.publish(frozen)
        self.assertEqual(
            GenerationClient(self.raw).smembers("tags:recent"), {"type:server"}
        )
        self.assertEqual(reconciliation_status(self.raw)["phase"], "up_to_date")

    def test_missing_parent_key_clears_partial_copy_and_keeps_tombstone(self):
        """Unowned leftovers cannot resurrect an empty field or mutate its parent."""
        self.publish(self.first)
        parent = GenerationClient(self.raw, writable=True)
        generation = "test-child"
        self.raw.set(f"{CONTROL}g:{generation}:parent", parent.chain()[0])
        key = generation_prefix(generation) + "banners:one"
        self.raw.sadd(key, "partial stale copy")
        child = GenerationClient(self.raw, generation, writable=True)
        child.delete("banners:one")
        self.assertFalse(self.raw.exists(key))
        self.assertTrue(self.raw.sismember(child.owned(generation), "banners:one"))
        parent.sadd("banners:one", "later parent value")
        self.assertFalse(child.exists("banners:one"))
        self.assertEqual(parent.smembers("banners:one"), {"later parent value"})

    def test_copy_error_preserves_ownership_and_retry(self):
        """Real copy errors propagate; retry restores complete inherited metadata."""
        self.publish(self.first)
        generation = "test-child"
        self.raw.set(f"{CONTROL}g:{generation}:parent", self.raw.get(ACTIVE))
        child = GenerationClient(self.raw, generation, writable=True)
        with patch.object(
            self.raw, "eval", side_effect=redis.ResponseError("storage unavailable")
        ):
            with self.assertRaisesRegex(redis.ResponseError, "storage unavailable"):
                child.hset("doc:one", mapping={"last_seen": "9999999999"})
        self.assertFalse(self.raw.sismember(child.owned(generation), "doc:one"))
        child.hset("doc:one", mapping={"last_seen": "9999999999"})
        self.assertEqual(child.hget("doc:one", "first_seen"), "100")
        self.assertEqual(child.hget("doc:one", "last_seen"), "9999999999")
        self.assertNotEqual(
            GenerationClient(self.raw).hget("doc:one", "last_seen"), "9999999999"
        )

    def test_lost_copy_response_does_not_repeat_completed_copy(self):
        self.publish(self.first)
        generation = "lost-copy-response"
        self.raw.set(f"{CONTROL}g:{generation}:parent", self.raw.get(ACTIVE))
        child = GenerationClient(self.raw, generation, writable=True)
        original = self.raw.eval

        def lost_response(*args):
            original(*args)
            raise redis.TimeoutError("response lost after COPY")

        with patch.object(self.raw, "eval", side_effect=lost_response):
            with self.assertRaises(redis.TimeoutError):
                child.hset("doc:one", mapping={"last_seen": "9999999999"})
        self.assertTrue(self.raw.sismember(child.owned(generation), "doc:one"))
        with patch.object(
            self.raw, "eval", side_effect=AssertionError("COPY repeated")
        ):
            child.hset("doc:one", mapping={"last_seen": "9999999999"})
        self.assertEqual(child.hget("doc:one", "first_seen"), "100")

    def test_failed_copy_job_resumes_same_frozen_inputs(self):
        """Recovery keeps its generation, candidates and rules despite later edits."""
        self.publish(self.first)
        changed = snapshot([("a", "port:443", ["type:server"])], {"server": True})
        queue_snapshot(self.raw, changed)
        worker = self.worker()
        worker.start()
        while not worker.job["candidates_ready"]:
            worker.prepare_candidates_batch()
        generation = worker.job["id"]
        inputs = self.raw.get(f"{CONTROL}g:{generation}:inputs")
        with patch.object(
            GenerationClient,
            "prepare_writes",
            side_effect=redis.ResponseError("no such key"),
        ):
            with self.assertRaisesRegex(redis.ResponseError, "no such key"):
                worker.run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "failed")
        queue_snapshot(self.raw, snapshot([("a", "port:22", ["proto:ssh"])]))
        self.worker().run()
        self.assertEqual(self.raw.get(ACTIVE), generation)
        self.assertEqual(self.raw.get(f"{CONTROL}g:{generation}:inputs"), inputs)
        self.assertEqual(read_json(self.raw, "published"), changed)


class ReconciliationIntegrationTest(ReconciliationCase):
    """Exercise real command ordering, COW ownership, journals and publication."""

    def test_search_timestamps_keep_pinned_parent_and_child_ownership(self):
        """Scalar reads preserve inherited keys, COW metadata and tombstones."""
        self.publish(self.first)
        scope = {"93.184.216.34": ["one"]}
        parent = index_for(GenerationClient(self.raw))
        expected_parent = search_timestamps(parent, scope)
        self.publish(snapshot([("a", "port:22", ["proto:ssh"])]))
        child = index_for(GenerationClient(self.raw, writable=True))
        self.assertEqual(search_timestamps(child, scope), expected_parent)
        child.r.hset("doc:one", mapping={"first_seen": 300, "last_seen": 400})
        self.assertEqual(
            search_timestamps(child, scope),
            {
                "93.184.216.34": {
                    "one": {"first_seen": 300, "last_seen": 400},
                    "min_seen": 300,
                    "max_seen": 400,
                }
            },
        )
        child.r.srem("ip:93.184.216.34", "one")
        self.assertEqual(
            search_timestamps(child, scope),
            {"93.184.216.34": {"min_seen": None, "max_seen": None}},
        )
        self.assertEqual(search_timestamps(parent, scope), expected_parent)

    def test_full_bootstrap_keeps_history_and_old_reader(self):
        """Full bootstrap keeps history and old reader."""
        old = GenerationClient(self.raw)
        self.assertEqual(old.smembers("tags:one"), {"type:server"})
        self.publish(self.first)
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("tags:one"), {"proto:https"})
        self.assertEqual(current.hgetall("doc:one")["first_seen"], "100")
        self.assertEqual(old.smembers("tags:one"), {"type:server"})
        self.assertEqual(current.smembers("tag:proto:https"), {"one"})

    def test_incremental_change_uses_no_meili_and_tombstones_empty_sets(self):
        """Incremental change uses no meili and tombstones empty sets."""
        self.publish(self.first)
        self.meili.reset_mock()
        after = snapshot([("a", "port:22", ["proto:ssh"])])
        self.publish(after)
        self.meili.get_document.assert_not_called()
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("tags:one"), set())
        self.assertEqual(current.smembers("tag:proto:https"), set())
        self.assertEqual(current.smembers("ports:one"), {"443"})

    def test_ingestion_during_build_is_replayed_before_switch(self):
        """Ingestion during build is replayed before switch."""
        queue_snapshot(self.raw, self.first)
        worker = self.worker()
        self.assertTrue(worker.start())
        self.scan(worker)
        incoming = source("two")
        self.documents["two"] = incoming
        ingest_sources(self.raw, [incoming], self.first)
        self.assertFalse(worker.replay_batch())
        self.assertTrue(worker.replay_batch())
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("tag:proto:https"), {"one", "two"})

    def test_interrupted_build_resumes_same_snapshot_despite_new_rules(self):
        """Interrupted build resumes same snapshot despite new rules."""
        queue_snapshot(self.raw, self.first)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        later = snapshot([("b", "port:443", ["type:server"])])
        queue_snapshot(self.raw, later)
        self.worker().run()
        self.assertEqual(
            read_json(self.raw, "published")["revision"], self.first["revision"]
        )
        self.worker().run()
        self.assertEqual(
            read_json(self.raw, "published")["revision"], later["revision"]
        )

    def test_source_failure_does_not_publish(self):
        """Source failure does not publish."""
        queue_snapshot(self.raw, self.first)
        self.meili.get_document.side_effect = RuntimeError("backend unavailable")
        with self.assertRaises(RuntimeError):
            self.worker().run()
        self.assertIsNone(self.raw.get(ACTIVE))
        self.assertEqual(read_json(self.raw, "job")["phase"], "failed")
        self.assertEqual(self.raw.smembers("tags:one"), {"type:server"})

    def test_new_uid_during_incremental_build_keeps_active_and_future_rules(self):
        """New uid during incremental build keeps active and future rules."""
        self.publish(self.first)
        next_state = snapshot([("a", "port:22", ["proto:ssh"])])
        queue_snapshot(self.raw, next_state)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        ingest_sources(self.raw, [source("two", "22")], next_state)
        self.assertEqual(GenerationClient(self.raw).smembers("tags:two"), set())
        while not worker.replay_batch():
            pass
        self.assertEqual(GenerationClient(self.raw).smembers("tags:two"), {"proto:ssh"})

    def test_changed_existing_uid_does_not_leave_old_reverse_membership(self):
        """Changed existing uid does not leave old reverse membership."""
        self.publish(self.first)
        next_state = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, next_state)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        ingest_sources(self.raw, [source("one", "22")], next_state)
        while not worker.replay_batch():
            pass
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("port:443"), set())
        self.assertEqual(current.smembers("port:22"), {"one"})
        self.assertEqual(current.smembers("tag:type:server"), set())

    def test_delete_during_build_does_not_resurrect_capture(self):
        """Replay a deletion after staging and remove both index directions."""
        self.publish(self.first)
        state = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, state)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        delete_capture(self.raw, "one")
        while not worker.replay_batch():
            pass
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("all_uids"), set())
        self.assertEqual(current.smembers("rule_matches:a"), set())
        self.assertEqual(current.smembers("tag:type:server"), set())

    def test_exact_changed_rule_does_not_reprocess_unrelated_uid(self):
        """Union old matches with the new positive seed, not all captures."""
        self.publish(self.first)
        ingest_sources(self.raw, [source("two", "80")], self.first)
        state = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, state)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        self.assertEqual(worker.job["total"], 1)
        self.assertEqual(worker.job["processed"], 1)
        self.assertEqual(
            self.raw.smembers(CONTROL + "processed:" + worker.job["id"]), {"one"}
        )

    def test_lost_commit_reply_does_not_corrupt_published_state(self):
        """A lost EXEC acknowledgement must not undo a successful publication."""
        queue_snapshot(self.raw, self.first)
        factory = self.raw.pipeline

        def pipeline(*args, **kwargs):
            pipe = factory(*args, **kwargs)
            execute = pipe.execute

            def execute_and_drop_reply():
                publishing = any(
                    command[0][0] == "SET" and command[0][1] == ACTIVE
                    for command in pipe.command_stack
                )
                result = execute()
                if publishing:
                    raise redis.ConnectionError("Publication committed; response lost")
                return result

            pipe.execute = execute_and_drop_reply
            return pipe

        with patch.object(self.raw, "pipeline", side_effect=pipeline):
            self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")
        self.assertEqual(
            GenerationClient(self.raw).smembers("tags:one"), {"proto:https"}
        )

    def test_invalid_snapshot_is_replaced_after_rule_correction(self):
        """Fixing a cyclic rule must unblock automatic processing without a button."""
        invalid = snapshot([("a", "port:443 AND tag:proto:https", ["proto:https"])])
        queue_snapshot(self.raw, invalid)
        with self.assertRaises(ValueError):
            self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "blocked")
        self.publish(self.first)
        self.assertEqual(
            GenerationClient(self.raw).smembers("tags:one"), {"proto:https"}
        )

    def test_subprocess_sigterm_checkpoints_and_resumes(self):
        """Exercise the real child stop handler across a process boundary."""
        queue_snapshot(self.raw, self.first)

        def child():
            raw = redis.Redis(
                unix_socket_path="/tmp/plum-271-test.sock",
                db=15,
                decode_responses=True,
                protocol=2,
            )
            worker = ReconciliationWorker(
                raw, self.meili, batch_size=1, pause_seconds=0.2
            )
            install_stop_handlers(worker)
            worker.run()

        process = multiprocessing.get_context("fork").Process(target=child)
        process.start()
        try:
            deadline = time.monotonic() + 5
            while read_json(self.raw, "job") is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNotNone(read_json(self.raw, "job"))
            process.terminate()
            process.join(timeout=5)
            self.assertFalse(process.is_alive())
            self.assertEqual(read_json(self.raw, "job")["phase"], "paused")
            self.assertIsNone(self.raw.get(ACTIVE))
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
            process.close()
        self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")

    def test_progress_records_do_not_repeat_frozen_rules(self):
        """Per-batch checkpoints stay small independently of the rule catalogue."""
        queue_snapshot(self.raw, self.first)
        worker = self.worker()
        worker.start()
        progress = read_json(self.raw, "job")
        self.assertNotIn("snapshot", progress)
        self.assertNotIn("candidate_sources", progress)
        inputs = read_json(self.raw, "g:" + worker.job["id"] + ":inputs")
        self.assertEqual(inputs["snapshot"], self.first)

    def test_cleanup_preserves_leased_generation_ancestors(self):
        """A cursor on a retired incremental generation still needs its parent."""
        self.publish(self.first)
        ancestor = self.raw.get(ACTIVE)
        changed = snapshot([("a", "port:443", ["type:server"])])
        self.publish(changed)
        leased = self.raw.get(ACTIVE)
        self.raw.set(f"{CONTROL}g:{leased}:lease:test", "1", ex=60)
        queue_snapshot(self.raw, changed, full=True)
        self.worker().run()
        self.assertNotEqual(self.raw.get(ACTIVE), leased)
        keys = list(retired_keys(self.raw))
        self.assertFalse(any(key.startswith(f"{CONTROL}g:{ancestor}:") for key in keys))
        self.assertFalse(any(key.startswith(f"{CONTROL}g:{leased}:") for key in keys))
        self.raw.delete(f"{CONTROL}g:{leased}:lease:test")
        keys = list(retired_keys(self.raw))
        self.assertIn(f"{CONTROL}g:{ancestor}:parent", keys)
        self.assertIn(f"{CONTROL}g:{leased}:parent", keys)

    def test_legacy_client_cannot_flush_or_write_after_enrollment(self):
        """Previously constructed clients cannot bypass managed writer guards."""
        old = GenerationClient(self.raw)
        self.assertEqual(old.smembers("tags:one"), {"type:server"})
        queue_snapshot(self.raw, self.first)
        with self.assertRaisesRegex(RuntimeError, "Managed index"):
            old.sadd("all_uids", "uncoordinated")
        with self.assertRaisesRegex(RuntimeError, "Managed index"):
            old.flushdb()
        self.assertIsNotNone(read_json(self.raw, "desired"))

    def test_header_collection_change_refreshes_coverage_without_rule_edit(self):
        """New search fields must not publish a profile that omits older captures."""
        self.publish(self.first)
        self.meili.reset_mock()
        changed = snapshot([("a", "port:443", ["proto:https"])], {"x-powered-by": True})
        self.publish(changed)
        self.meili.get_document.assert_called_once_with("one")
        current = GenerationClient(self.raw)
        profile = read_json(self.raw, "coverage:" + current.get("coverage:one"))
        self.assertEqual(profile["parser"], changed["parser"])


class ReparseDeltaIntegrationTest(ReconciliationCase):
    """Verify the selective writer against full writes and journal replay."""

    def reparse(self, rules):
        """Queue an incremental coverage change and return its worker."""
        queue_snapshot(self.raw, snapshot(rules, {"server": True}))
        worker = self.worker()
        self.assertTrue(worker.start())
        return worker

    def test_identical_capture_updates_coverage_and_inherits_history(self):
        """Skip unchanged fields, dates, tags and rule contributions."""
        self.publish(self.first)
        parent = GenerationClient(self.raw, self.raw.get(ACTIVE))
        worker = self.reparse([("a", "port:443", ["proto:https"])])
        self.scan(worker)
        staged = GenerationClient(self.raw, worker.job["id"])
        self.assertEqual(
            self.raw.smembers(staged.owned(staged.generation)),
            {"coverage:one", "tag_catalogue"},
        )
        self.assertNotEqual(staged.get("coverage:one"), parent.get("coverage:one"))
        self.assertEqual(staged.hgetall("doc:one"), parent.hgetall("doc:one"))
        self.assertEqual(staged.zscore("first_seen_index", "one"), 100)
        self.assertEqual(staged.smembers("tag:proto:https"), {"one"})
        self.assertTrue(worker.replay_batch())

    def test_changed_tags_and_producers_update_both_index_directions(self):
        """Remove old memberships and retain unchanged shared tags."""
        self.first = snapshot(
            [
                ("a", "port:443", ["proto:https", "type:server"]),
                ("shared", "port:443", ["type:server"]),
            ]
        )
        self.publish(self.first)
        parent = GenerationClient(self.raw, self.raw.get(ACTIVE))
        worker = self.reparse(
            [
                ("b", "port:443", ["proto:tls"]),
                ("shared", "port:443", ["type:server"]),
            ]
        )
        self.scan(worker)
        self.assertTrue(worker.replay_batch())
        active = GenerationClient(self.raw, worker.job["id"])
        self.assertNotIn(
            "ports:one", self.raw.smembers(active.owned(active.generation))
        )
        self.assertEqual(active.smembers("tags:one"), {"proto:tls", "type:server"})
        self.assertEqual(active.smembers("tag:proto:tls"), {"one"})
        self.assertEqual(active.smembers("tag:type:server"), {"one"})
        self.assertFalse(active.smembers("tag:proto:https"))
        self.assertFalse(active.smembers("rule_matches:a"))
        self.assertEqual(active.smembers("rule_matches:b"), {"one"})
        self.assertEqual(active.smembers("rule_matches:shared"), {"one"})
        self.assertEqual(
            json.loads(active.get("contributions:one")),
            {"b": ["proto:tls"], "shared": ["type:server"]},
        )
        self.assertIn("proto:tls", active.smembers("tag_catalogue"))
        self.assertEqual(parent.smembers("tag:proto:https"), {"one"})

    def test_changed_capture_fields_and_legacy_metadata_use_full_write(self):
        """Refresh changed search fields and remove old storage markers."""
        self.documents["legacy"] = source("legacy")
        self.publish(self.first)
        parent = GenerationClient(self.raw, self.raw.get(ACTIVE), writable=True)
        parent.hset("doc:legacy", mapping={"nse_marker": "old"})
        self.documents["one"] = source("one", "22", "2026-09-12T00:00:00")
        worker = self.reparse([("a", "port:443", ["proto:https"])])
        self.scan(worker)
        self.assertTrue(worker.replay_batch())
        active = GenerationClient(self.raw)
        self.assertEqual(active.smembers("ports:one"), {"22"})
        self.assertEqual(active.smembers("port:22"), {"one"})
        self.assertEqual(active.smembers("port:443"), {"legacy"})
        self.assertEqual(active.zscore("first_seen_index", "one"), 100)
        self.assertGreater(
            active.zscore("last_seen_index", "one"),
            parent.zscore("last_seen_index", "one"),
        )
        self.assertIsNone(active.hget("doc:legacy", "nse_marker"))

    def test_parent_write_between_read_and_save_uses_full_path_and_replays(self):
        """A foreground mutation invalidates the batch's comparison snapshot."""
        self.publish(self.first)
        worker = self.reparse([("a", "port:443", ["type:server"])])
        latest = source("one", "22", "2026-09-12T00:00:00")

        def ingest_during_read(uid):
            """Mutate the active capture after the worker has loaded it."""
            ingest_sources(self.raw, [latest], self.first)
            return Document(deepcopy(self.documents[uid]))

        self.meili.get_document.side_effect = ingest_during_read
        self.scan(worker)
        self.assertIn(
            "doc:one", self.raw.smembers(GenerationClient.owned(worker.job["id"]))
        )
        self.assertFalse(worker.replay_batch())
        self.assertTrue(worker.replay_batch())
        active = GenerationClient(self.raw)
        self.assertEqual(active.smembers("ports:one"), {"22"})
        self.assertFalse(active.smembers("port:443"))
        self.assertFalse(active.smembers("tag:type:server"))
        self.assertEqual(active.zscore("first_seen_index", "one"), 100)

    def test_retry_after_delta_write_rechecks_staging(self):
        """An interrupted progress write keeps the staged data resumable."""
        self.publish(self.first)
        worker = self.reparse([("b", "port:443", ["type:server"])])
        generation = worker.job["id"]
        sadd = self.raw.sadd

        def fail_progress(key, *values):
            """Let the delta commit, then interrupt its progress update."""
            if key == CONTROL + "processed:" + generation:
                raise redis.ConnectionError("Progress write interrupted")
            return sadd(key, *values)

        with patch.object(self.raw, "sadd", side_effect=fail_progress):
            with self.assertRaisesRegex(
                redis.ConnectionError, "Progress write interrupted"
            ):
                worker.run()
        staged = GenerationClient(self.raw, generation)
        self.assertEqual(staged.smembers("tags:one"), {"type:server"})
        self.assertNotIn("doc:one", self.raw.smembers(staged.owned(generation)))
        self.worker().run()
        self.assertEqual(self.raw.get(ACTIVE), generation)
        self.assertIn("doc:one", self.raw.smembers(staged.owned(generation)))
        self.assertEqual(staged.smembers("rule_matches:b"), {"one"})
        self.assertFalse(staged.smembers("rule_matches:a"))


class RetagIntegrationTest(ReconciliationCase):
    """Chronological retagging and checkpoint handoff regressions."""

    def test_newest_first_retag_resumes_after_a_partially_processed_batch(self):
        """Planning order is independent of UID, insertion and restart order."""
        self.publish(self.first)
        captures = [
            source("z-old", endtime="2026-09-11T00:00:00"),
            source("a-new", endtime="2026-09-13T00:00:00"),
            source("b-middle", endtime="2026-09-12T00:00:00"),
        ]
        ingest_sources(self.raw, captures, self.first)
        changed = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, changed)
        worker = self.worker()
        worker.batch_size = 3
        worker.start()
        while not worker.job["candidates_ready"]:
            worker.prepare_candidates_batch()
        worker._claim_candidates()  # pylint: disable=protected-access
        self.assertEqual(worker.job["pending_uids"], ["a-new", "b-middle", "z-old"])
        worker.process_uid("a-new")  # Interrupted before the batch checkpoint.
        self.meili.get_document.reset_mock()
        resumed = self.worker()
        with patch.object(resumed, "process_uid", wraps=resumed.process_uid) as process:
            resumed.run()
        self.assertEqual(
            [call.args[0] for call in process.call_args_list],
            ["b-middle", "z-old", "one"],
        )
        self.meili.get_document.assert_not_called()
        self.assertEqual(read_json(self.raw, "published"), changed)

    def test_fast_retag_switches_at_checkpoint_and_replays_inherited_journal(self):
        """Replace staging at a batch boundary, including writes absent from the parent."""
        self.publish(self.first)
        parent = self.raw.get(ACTIVE)
        old = snapshot([("a", "port:443", ["type:server"])])
        skipped = snapshot([("a", "port:443", ["proto:ssh"])])
        latest = snapshot([("a", "port:443", ["proto:tls"])])
        ingest_sources(self.raw, [source("removed")], self.first)
        queue_snapshot(self.raw, old)
        worker = self.worker()
        worker.start()
        original_job = worker.job["id"]

        def process(uid):
            """Edit twice and inject ingestion failure at the old batch boundary."""
            ReconciliationWorker.process_uid(worker, uid)
            if worker.job["id"] != original_job:
                self.assertNotIn(
                    CONTROL + "journal:" + original_job, set(retired_keys(self.raw))
                )
                ingest_sources(self.raw, [source("after-switch")], latest)
                return
            queue_snapshot(self.raw, skipped)
            with patch(
                "app.utils.index_reconciliation.save_document",
                side_effect=OSError("active write failed"),
            ):
                with self.assertRaisesRegex(OSError, "active write failed"):
                    ingest_sources(
                        self.raw, [source("journal-only")], old, live_snapshot=skipped
                    )
            delete_capture(self.raw, "removed")
            ingest_sources(
                self.raw,
                [source("one", endtime="2026-09-14T00:00:00")],
                old,
                live_snapshot=skipped,
            )
            queue_snapshot(self.raw, latest)

        with patch.object(worker, "process_uid", side_effect=process):
            worker.run()
        index = GenerationClient(self.raw)
        job = read_json(self.raw, "job")
        self.assertEqual(job["parent"], parent)
        self.assertEqual(job["journal_id"], original_job)
        self.assertEqual(job["journal_offset"], 4)
        self.assertEqual(read_json(self.raw, "published"), latest)
        expected = {"one", "journal-only", "after-switch"}
        self.assertEqual(index.smembers("all_uids"), expected)
        self.assertEqual(index.smembers("tag:proto:tls"), expected)
        self.assertFalse(index.smembers("tag:proto:ssh"))
        self.assertFalse(index.smembers("tag:type:server"))
        self.assertEqual(index.hget("doc:one", "first_seen"), "100")
        self.assertEqual(index.hget("doc:one", "last_seen"), "1789344000")

    def test_retag_revert_at_cutover_skips_obsolete_publication(self):
        """A revision received after scanning still wins before the pointer flip."""
        self.publish(self.first)
        parent = self.raw.get(ACTIVE)
        changed = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, changed)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        queue_snapshot(self.raw, self.first)
        self.assertFalse(worker.replay_batch())
        self.assertEqual(self.raw.get(ACTIVE), parent)
        self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["parent"], parent)
        self.assertEqual(read_json(self.raw, "published"), self.first)

    def test_retag_switch_lost_reply_recovers_new_job_and_journal(self):
        """A crash after the handoff transaction resumes the installed job."""
        self.publish(self.first)
        changed = snapshot([("a", "port:443", ["type:server"])])
        latest = snapshot([("a", "port:443", ["proto:tls"])])
        queue_snapshot(self.raw, changed)
        worker = self.worker()
        worker.start()
        original_job = worker.job["id"]
        ingest_sources(self.raw, [source("journalled")], changed)
        queue_snapshot(self.raw, latest)
        factory = self.raw.pipeline

        def pipeline(*args, **kwargs):
            pipe = factory(*args, **kwargs)
            execute = pipe.execute

            def drop_handoff_reply():
                handoff = any(
                    cmd[0][0] == "SET" and cmd[0][1].endswith(":parent")
                    for cmd in pipe.command_stack
                )
                result = execute()
                if handoff:
                    raise redis.ConnectionError(
                        "Handoff committed before connection lost"
                    )
                return result

            pipe.execute = drop_handoff_reply
            return pipe

        with patch.object(self.raw, "pipeline", side_effect=pipeline):
            with self.assertRaisesRegex(redis.ConnectionError, "Handoff committed"):
                worker.run()
        job = read_json(self.raw, "job")
        self.assertEqual(job["snapshot_revision"], latest["revision"])
        self.assertEqual(job["journal_id"], original_job)
        self.worker().run()
        self.assertEqual(self.raw.get(ACTIVE), job["id"])
        self.assertEqual(
            GenerationClient(self.raw).smembers("tag:proto:tls"), {"one", "journalled"}
        )


class ReconciliationRecoveryTest(ReconciliationCase):
    """Recover historical persisted jobs and interrupted checkpoint creation."""

    def legacy_job(self, worker, phase):
        """Reproduce the original inline format, before candidate planning existed."""
        job = deepcopy(worker.job)
        for key in (
            "candidate_sources",
            "candidate_source",
            "candidate_cursor",
            "candidates_ready",
            "ordered_candidates",
            "planned_total",
            "snapshot_revision",
        ):
            job.pop(key, None)
        job["phase"] = phase
        write_json(self.raw, "job", job)
        self.raw.delete(CONTROL + "g:" + job["id"] + ":inputs")
        return job

    def test_superseded_blocked_inline_job_starts_current_revision(self):
        """Recover the reported pre-migration job without requiring a missing key."""
        queue_snapshot(self.raw, self.first)
        worker = self.worker()
        worker.start()
        legacy = self.legacy_job(worker, "blocked")
        self.assertEqual(
            reconciliation_status(self.raw)["revision"], self.first["revision"][:12]
        )
        changed = snapshot([("a", "port:443", ["type:server"])])
        self.publish(changed)
        self.assertNotEqual(self.raw.get(ACTIVE), legacy["id"])
        self.assertEqual(
            GenerationClient(self.raw).smembers("tags:one"), {"type:server"}
        )

    def test_inline_job_migration_preserves_frozen_rules_and_journal(self):
        """Replan old scan cursors while retaining staged data and ordered ingestion."""
        self.publish(self.first)
        frozen = snapshot([("a", "port:443", ["type:server"])], {"server": True})
        queue_snapshot(self.raw, frozen)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        self.documents["two"] = source("two")
        ingest_sources(self.raw, [self.documents["two"]], frozen)
        legacy = self.legacy_job(worker, "paused")
        latest = snapshot([("a", "port:22", ["proto:ssh"])])
        queue_snapshot(self.raw, latest)
        self.worker().run()
        self.assertEqual(self.raw.get(ACTIVE), legacy["id"])
        self.assertEqual(read_json(self.raw, "published"), frozen)
        self.assertEqual(
            GenerationClient(self.raw).smembers("tag:type:server"), {"one", "two"}
        )
        inputs = read_json(self.raw, "g:" + legacy["id"] + ":inputs")
        self.assertEqual(inputs["snapshot"], frozen)
        self.assertNotIn("snapshot", read_json(self.raw, "job"))
        self.worker().run()
        self.assertEqual(read_json(self.raw, "published"), latest)

    def test_completed_job_does_not_require_its_frozen_inputs(self):
        """Completed jobs do not need resumption when the next revision arrives."""
        self.publish(self.first)
        self.raw.delete(CONTROL + "g:" + self.raw.get(ACTIVE) + ":inputs")
        self.publish(snapshot([("a", "port:443", ["type:server"])]))
        self.assertEqual(
            GenerationClient(self.raw).smembers("tags:one"), {"type:server"}
        )

    def test_missing_inputs_block_safely_and_allow_forced_rebuild(self):
        """Never guess frozen inputs; retain active data and expose CLI recovery."""
        queue_snapshot(self.raw, self.first)
        worker = self.worker()
        worker.start()
        self.raw.delete(CONTROL + "g:" + worker.job["id"] + ":inputs")
        write_json(self.raw, "failure", {"phase": "failed", "message": "Old failure"})
        with self.assertRaisesRegex(ValueError, "Missing frozen reconciliation inputs"):
            self.worker().run()
        job = read_json(self.raw, "job")
        self.assertEqual(job["phase"], "blocked")
        self.assertIn("--flush", job["message"])
        self.assertEqual(reconciliation_status(self.raw)["phase"], "blocked")
        self.assertIsNone(self.raw.get(ACTIVE))
        self.assertEqual(self.raw.smembers("tags:one"), {"type:server"})
        queue_snapshot(self.raw, self.first, full=True)
        self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")

    def test_first_checkpoint_failure_cannot_leave_job_without_inputs(self):
        """A failed initial transaction leaves no partially installed job."""
        queue_snapshot(self.raw, self.first)
        factory = self.raw.pipeline
        failed = False

        def pipeline(*args, **kwargs):
            pipe = factory(*args, **kwargs)
            execute = pipe.execute

            def fail_first_checkpoint():
                nonlocal failed
                checkpoint = any(
                    command[0][:2] == ("SET", CONTROL + "job")
                    for command in pipe.command_stack
                )
                if checkpoint and not failed:
                    failed = True
                    raise redis.ConnectionError("First checkpoint interrupted")
                return execute()

            pipe.execute = fail_first_checkpoint
            return pipe

        with patch.object(self.raw, "pipeline", side_effect=pipeline):
            with self.assertRaises(redis.ConnectionError):
                self.worker().run()
        self.assertIsNone(read_json(self.raw, "job"))
        self.assertEqual(read_json(self.raw, "failure")["phase"], "failed")
        self.worker().run()
        job = read_json(self.raw, "job")
        inputs = read_json(self.raw, "g:" + job["id"] + ":inputs")
        self.assertEqual(inputs["snapshot"], self.first)
        self.assertEqual(job["phase"], "done")


class ReconciliationPacingTest(ReconciliationCase):
    """Exercise pacing against real Redis commands and existing frozen jobs."""

    def paced(self, *, exports_pending=None, **overrides):
        """Use immediate quiet detection in protocol checks, not production tuning."""
        return PacedReconciliationWorker(
            self.raw,
            self.meili,
            {
                "TAG_RECONCILIATION_BATCH_SIZE": 1,
                "TAG_RECONCILIATION_QUIET_SECONDS": 0,
                "TAG_RECONCILIATION_IDLE_SECONDS": 0,
                "TAG_RECONCILIATION_PAUSE_SECONDS": 0,
                **overrides,
            },
            exports_pending=exports_pending,
        )

    def missing_document(self, code="document_not_found"):
        """Model a typed Meilisearch 404, including its SDK error code."""
        response = Response()
        response.status_code = 404
        response._content = json.dumps({"code": code, "message": code}).encode()
        return MeilisearchApiError(code, response)

    def test_missing_source_does_not_block_full_rebuild_or_later_recovery(self):
        """A full generation copies the capture and the worker retries it later."""
        del self.documents["one"]
        self.documents["two"] = source("two")

        def read_source(uid):
            if uid == "one":
                raise self.missing_document()
            return Document(self.documents[uid])

        self.meili.get_document.side_effect = read_source
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.scan(worker)
        worker.checkpoint(phase="paused")
        self.paced().run()
        old_generation = self.raw.get(ACTIVE)
        self.assertEqual(old_generation, worker.job["id"])
        current = GenerationClient(self.raw)
        self.assertEqual(current.smembers("all_uids"), {"one", "two"})
        self.assertEqual(current.smembers("tags:one"), {"type:server"})
        self.assertEqual(
            current.hmget("doc:one", "first_seen", "last_seen"), ["100", "200"]
        )
        self.assertEqual(current.smembers("tags:two"), {"proto:https"})
        self.assertEqual(pacing_status(self.raw)["missing_sources"], 1)
        self.assertEqual(read_json(self.raw, "job")["processed"], 2)

        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        supervisor = IndexSupervisor(self.raw, {})
        with patch("app.utils.index_supervisor.subprocess.Popen") as process:
            supervisor.tick(self.first)
        process.assert_called_once()

        self.meili.get_document.side_effect = None
        self.meili.get_document.return_value = Document(source())
        self.paced().run()
        self.assertEqual(self.raw.get(ACTIVE), old_generation)
        self.assertEqual(current.smembers("tags:one"), {"proto:https"})
        self.assertEqual(current.hget("doc:one", "first_seen"), "100")
        self.assertEqual(self.raw.zcard(MISSING_SOURCES), 0)

    def test_missing_source_keeps_recent_and_pending_captures(self):
        """An expired missing capture is removable once both export queues drain."""
        self.raw.hset("doc:one", "last_seen", str(int(time.time())))
        del self.documents["one"]
        self.meili.get_document.side_effect = self.missing_document()
        self.meili.get_stats.return_value = SimpleNamespace(
            number_of_documents=1, is_indexing=False
        )
        self.meili.get_tasks.return_value = SimpleNamespace(results=[])
        exports_pending = Mock(return_value=False)
        queue_snapshot(self.raw, self.first)
        self.paced(exports_pending=exports_pending).run()
        current = GenerationClient(self.raw, writable=True)

        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        self.paced(exports_pending=exports_pending).run()
        self.assertTrue(current.sismember("all_uids", "one"))
        exports_pending.assert_not_called()

        current.hset("doc:one", "last_seen", "200")
        exports_pending.return_value = True
        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        self.paced(exports_pending=exports_pending).run()
        self.assertTrue(current.sismember("all_uids", "one"))

        exports_pending.return_value = False
        self.meili.get_tasks.return_value = SimpleNamespace(results=[object()])
        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        self.paced(exports_pending=exports_pending).run()
        self.assertTrue(current.sismember("all_uids", "one"))

        self.meili.get_tasks.return_value = SimpleNamespace(results=[])
        self.meili.get_document.side_effect = [
            self.missing_document(),
            Document(source()),
        ]
        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        self.paced(exports_pending=exports_pending).run()
        self.assertTrue(current.sismember("all_uids", "one"))

        self.meili.get_document.side_effect = self.missing_document()
        self.raw.zadd(MISSING_SOURCES, {"one": 0})
        self.paced(exports_pending=exports_pending).run()
        self.assertFalse(current.sismember("all_uids", "one"))
        self.assertFalse(current.exists("doc:one"))
        self.assertFalse(current.sismember("tag:type:server", "one"))
        self.assertEqual(self.raw.zcard(MISSING_SOURCES), 0)

    def test_missing_index_error_cannot_skip_an_indexed_capture(self):
        """A missing endpoint/index remains a failing rebuild."""
        del self.documents["one"]
        self.meili.get_document.side_effect = self.missing_document("index_not_found")
        queue_snapshot(self.raw, self.first)
        with self.assertRaises(MeilisearchApiError):
            self.paced().run()
        self.assertIsNone(self.raw.get(ACTIVE))
        self.assertEqual(self.raw.zcard(MISSING_SOURCES), 0)

    def test_planning_batches_are_independent_of_processing_batch(self):
        """Small capture batches no longer require one sleep per handful of IDs."""
        self.raw.sadd("all_uids", *[f"candidate-{index}" for index in range(200)])
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        worker.prepare_candidates_batch()
        self.assertEqual(
            self.raw.scard(CONTROL + "candidates:" + worker.job["id"]), 201
        )
        self.assertEqual(worker.batch_size, 1)

    def test_source_batch_spans_checkpoints_and_resumes_in_last_seen_order(self):
        """Prefetch 32, checkpoint at 25, and resume with the live journal."""
        self.publish(self.first)
        captures = [
            source(f"capture-{i:02}", endtime=f"2026-09-15T00:{i // 60:02}:{i % 60:02}")
            for i in range(69)
        ]
        self.documents.update((capture["id"], capture) for capture in captures)
        ingest_sources(self.raw, captures, self.first)
        expected = [capture["id"] for capture in reversed(captures)] + ["one"]
        newest = expected[0]
        changed = snapshot([("a", "port:443", ["type:server"])], {"server": True})
        queue_snapshot(self.raw, changed)
        self.meili.reset_mock()
        worker = self.paced(TAG_RECONCILIATION_BATCH_SIZE=25)
        seen = []

        def interrupt(uid):
            """Stop with a partially consumed batch and a journal entry."""
            seen.append(uid)
            if len(seen) == 26:
                self.assertEqual(read_json(self.raw, "job")["processed"], 25)
            PacedReconciliationWorker.process_uid(worker, uid)
            if len(seen) == 27:
                ingest_sources(
                    self.raw, [source(newest, "22", "2026-09-16T00:00:00")], changed
                )
                worker.stopping = True

        with patch.object(worker, "process_uid", side_effect=interrupt):
            worker.run()
        saved = read_json(self.raw, "job")
        self.assertEqual(saved["processed"], 27)
        self.assertEqual(saved["pending_uids"], expected[27:32])
        self.assertEqual(saved["phase"], "paused")
        resumed = self.paced(
            TAG_RECONCILIATION_BATCH_SIZE=25, TAG_RECONCILIATION_MEILI_BATCH_SIZE=24
        )
        with patch.object(resumed, "process_uid", wraps=resumed.process_uid) as process:
            resumed.run()
        self.assertEqual(
            seen + [call.args[0] for call in process.call_args_list], expected
        )
        self.assertEqual(
            [call.args[0]["ids"] for call in self.meili.get_documents.call_args_list],
            [expected[:32], expected[27:32], expected[32:56], expected[56:]],
        )
        self.meili.get_document.assert_not_called()
        self.assertEqual(self.raw.get(ACTIVE), saved["id"])
        self.assertEqual(read_json(self.raw, "job")["journal_offset"], 1)
        index = GenerationClient(self.raw)
        self.assertEqual(index.smembers(f"ports:{newest}"), {"22"})
        self.assertEqual(index.smembers("tag:type:server"), set(expected) - {newest})

    def test_bootstrap_excludes_private_meili_only_source_and_resumes(self):
        """Reference parsing ignores private-only sources; bootstrap must finish."""
        self.documents["private"] = dict(source("private"), ip="10.0.0.1")
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.scan(worker)
        worker.checkpoint(phase="paused")
        saved = read_json(self.raw, "job")
        self.assertEqual(saved["excluded_sources"], 1)
        resumed = self.paced()
        resumed.run()
        final = read_json(self.raw, "job")
        self.assertEqual(final["id"], saved["id"])
        self.assertEqual(final["phase"], "done")
        self.assertEqual(final["processed"], 2)
        self.assertEqual(GenerationClient(self.raw).smembers("all_uids"), {"one"})
        self.assertEqual(
            GenerationClient(self.raw).smembers("tag:proto:https"), {"one"}
        )
        self.assertEqual(json.loads(self.raw.get(PACING))["excluded_sources"], 1)

    def test_excluded_source_cannot_hide_existing_indexed_history(self):
        """A source/index disagreement requires review, never silent deletion."""
        self.documents["one"]["ip"] = "10.0.0.1"
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        with self.assertRaises(SnapshotInvalid):
            worker.run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "blocked")
        self.assertIsNone(self.raw.get(ACTIVE))
        self.assertEqual(GenerationClient(self.raw).smembers("all_uids"), {"one"})
        supervisor = IndexSupervisor(self.raw, {})
        with patch("app.utils.index_supervisor.subprocess.Popen") as process:
            supervisor.tick(self.first)
        process.assert_not_called()

    def orphan(self):
        """Retained timestamp hash matching the legacy rebuild's documented case."""
        self.documents["private"] = dict(source("private"), ip="10.0.0.1")
        metadata = {"ip": "10.0.0.1", "first_seen": "100", "last_seen": "200"}
        self.raw.hset("doc:private", mapping=metadata)
        return metadata

    def test_excluded_orphan_dates_survive_publication_and_restart(self):
        """Keep detached dates verbatim without inventing searchable captures."""
        metadata = self.orphan()
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.scan(worker)
        worker.checkpoint(phase="paused")
        generation = worker.job["id"]
        self.paced().run()
        current = GenerationClient(self.raw)
        self.assertEqual(current.hgetall("doc:private"), metadata)
        self.assertEqual(self.raw.hgetall("doc:private"), metadata)
        self.assertEqual(current.smembers("all_uids"), {"one"})
        self.assertFalse(current.exists("uid:private"))
        self.assertIsNone(current.zscore("last_seen_index", "private"))
        self.assertEqual(read_json(self.raw, "job")["id"], generation)
        self.assertEqual(read_json(self.raw, "job")["excluded_sources"], 1)

    def test_partial_or_conflicting_orphan_data_remains_blocked(self):
        """Missing all_uids alone cannot make existing history safe to exclude."""
        self.orphan()
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        target = GenerationClient(self.raw, worker.job["id"], writable=True)
        cases = (
            (lambda: self.raw.set("uid:private", "10.0.0.1"), "uid:private"),
            (lambda: self.raw.sadd("ip:10.0.0.1", "private"), "ip:10.0.0.1"),
            (lambda: self.raw.zadd("last_seen_index", {"private": 0}), None),
            (lambda: self.raw.sadd("ports:private", "443"), "ports:private"),
            (lambda: self.raw.set("coverage:private", "old"), "coverage:private"),
            (
                lambda: target.hset("doc:private", mapping={"ip": "10.0.0.2"}),
                None,
            ),
        )
        for mutation, cleanup in cases:
            with self.subTest(cleanup=cleanup):
                mutation()
                with self.assertRaises(SnapshotInvalid):
                    worker.process_uid("private")
                if cleanup:
                    self.raw.delete(cleanup)
                self.raw.zrem("last_seen_index", "private")
                target.delete("doc:private")
        self.raw.hset("doc:private", "unexpected", "retain-me")
        with self.assertRaises(SnapshotInvalid):
            worker.process_uid("private")
        self.assertEqual(worker.load.excluded, 0)

    def test_failed_orphan_copy_is_retried_before_exclusion_is_recorded(self):
        """An interrupted copy must not mark the source as processed."""
        metadata = self.orphan()
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        execute = GenerationClient.run

        def failing(client, commands):
            if any(name == "hset" for name, _args, _kwargs in commands):
                raise redis.ConnectionError("copy interrupted")
            return execute(client, commands)

        with patch.object(GenerationClient, "run", failing):
            with self.assertRaises(redis.ConnectionError):
                worker.process_uid("private")
        self.assertFalse(
            self.raw.sismember(CONTROL + "processed:" + worker.job["id"], "private")
        )
        worker.process_uid("private")
        target = GenerationClient(self.raw, worker.job["id"])
        self.assertEqual(target.hgetall("doc:private"), metadata)

    def test_scheduler_recovers_known_orphan_block_once_with_same_inputs(self):
        """Upgrade resumes the existing job through its normal scheduler owner."""
        self.orphan()
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        worker.checkpoint(
            phase="blocked",
            message=SOURCE_CONFLICT,
            pending_uids=["private"],
            retry_at=time.time() + 3600,
        )
        before = read_json(self.raw, "job")
        inputs = self.raw.get(CONTROL + "g:" + before["id"] + ":inputs")
        supervisor = IndexSupervisor(self.raw, {})
        with patch("app.utils.index_supervisor.subprocess.Popen") as process:
            supervisor.tick(self.first)
        process.assert_called_once()
        resumed = read_json(self.raw, "job")
        for field in set(before) - {"phase", "message", "retry_at"}:
            self.assertEqual(resumed[field], before[field])
        self.assertEqual(resumed["phase"], "paused")
        self.assertIsNone(resumed["retry_at"])
        self.assertEqual(
            self.raw.get(CONTROL + "g:" + before["id"] + ":inputs"), inputs
        )
        # A changed source can still fail normal validation; never restart-loop.
        self.documents["private"]["ip"] = "10.0.0.2"
        with self.assertRaises(SnapshotInvalid):
            self.paced().run()
        blocked = read_json(self.raw, "job")
        self.assertEqual(requeue_orphan_exclusion(self.raw, blocked), blocked)
        self.assertEqual(blocked["phase"], "blocked")

    def test_journal_update_after_exclusion_is_still_applied(self):
        """An exclusion marker cannot suppress a later valid source update."""
        self.documents["later"] = dict(source("later"), ip="10.0.0.1")
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.scan(worker)
        ingest_sources(self.raw, [source("later")], self.first)
        worker.run()
        self.assertEqual(
            GenerationClient(self.raw).smembers("tag:proto:https"), {"one", "later"}
        )
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")

    def test_malformed_or_missing_source_still_fails(self):
        """No general exception handler may turn unavailable data into success."""
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.documents["malformed"] = dict(source("malformed"), ip="invalid")
        for uid, exception in (("malformed", ValueError), ("missing", KeyError)):
            with self.subTest(uid=uid), self.assertRaises(exception):
                worker.process_uid(uid)
            self.assertFalse(
                self.raw.sismember(CONTROL + "processed:" + worker.job["id"], uid)
            )
        self.assertEqual(worker.load.excluded, 0)

    def test_runtime_upgrade_resumes_original_job_and_cursor(self):
        """Runtime pacing must not invalidate frozen parser/rule fingerprints."""
        queue_snapshot(self.raw, self.first)
        original = self.worker()
        original.start()
        original.prepare_candidates_batch()
        saved = read_json(self.raw, "job")
        upgraded = self.paced()
        upgraded.start()
        self.assertEqual(upgraded.job["id"], saved["id"])
        self.assertEqual(upgraded.job["candidate_cursor"], saved["candidate_cursor"])
        self.assertEqual(upgraded.job["candidate_source"], saved["candidate_source"])
        upgraded.run()
        self.assertEqual(self.raw.get(ACTIVE), saved["id"])
        self.assertEqual(read_json(self.raw, "published"), self.first)
        self.assertEqual(json.loads(self.raw.get(PACING))["mode"], "stopped")

    def test_search_and_ingestion_leases_release_and_expire(self):
        """Foreground completion or process death cannot pause indexing forever."""
        worker = self.paced()
        monitor = ActivityMonitor(self.raw)
        with patch("app.utils.index_activity.threading.Thread"):
            for kind in ("search", "ingestion"):
                lease = monitor.begin(kind)
                self.assertIsNotNone(lease)
                self.assertFalse(worker.load.ready())
                lease.finish()
                self.assertTrue(worker.load.ready())
        self.raw.zadd(ACTIVITY + "search", {"crashed-reader": time.time() - 1})
        self.assertTrue(worker.load.ready())

    def test_upgrade_ignores_old_query_and_timestamp_timings(self):
        """Earlier signatures and slower timestamp reads cannot seed baselines."""
        samples = [
            {"id": str(index), "signature": "mixed", "seconds": 1, "baseline": True}
            for index in range(3)
        ]
        samples.append(
            {"id": "slow", "signature": "mixed", "seconds": 5, "baseline": False}
        )
        for name in ("samples", "samples:v2"):
            self.raw.rpush(ACTIVITY + name, *[json.dumps(item) for item in samples])
        controller = self.paced().load
        controller.observe_latency()
        self.assertEqual(controller.factor, 1)
        self.assertEqual(controller.comparisons, 0)
        with patch("app.utils.index_activity.threading.Thread"):
            lease = ActivityMonitor(self.raw).begin(signature="new-query")
            lease.finish()
        self.assertEqual(self.raw.llen(SAMPLES), 1)
        self.assertEqual(self.raw.llen(ACTIVITY + "samples"), 4)
        self.assertEqual(self.raw.llen(ACTIVITY + "samples:v2"), 4)

    def test_stop_during_priority_wait_preserves_pending_work(self):
        """A stop while users are active must not consume a pending capture."""
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        while not worker.job["candidates_ready"]:
            worker.prepare_candidates_batch()
        before = read_json(self.raw, "job")

        def stop(_check):
            worker.stopping = True
            return False

        with patch.object(worker.load, "wait", side_effect=stop):
            worker.run()
        after = read_json(self.raw, "job")
        self.assertEqual(after["phase"], "paused")
        self.assertEqual(after["pending_uids"], before["pending_uids"])
        self.assertEqual(after["processed"], 0)
        self.assertIsNone(self.raw.get(ACTIVE))

    def test_priority_is_checked_between_replayed_journal_entries(self):
        """A busy replay batch can stop after one entry and resume without loss."""
        queue_snapshot(self.raw, self.first)
        worker = self.paced()
        worker.start()
        self.scan(worker)
        ingest_sources(self.raw, [source("two"), source("three")], self.first)
        worker.batch_size = 25
        with patch.object(worker.load, "wait", side_effect=[True, False]):
            self.assertFalse(worker.replay_batch())
        self.assertEqual(worker.job["journal_offset"], 1)
        self.assertIsNone(self.raw.get(ACTIVE))
        self.assertTrue(worker.replay_batch())
        self.assertEqual(
            GenerationClient(self.raw).smembers("tag:proto:https"),
            {"one", "two", "three"},
        )


if __name__ == "__main__":
    unittest.main()
