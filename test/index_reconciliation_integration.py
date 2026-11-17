"""Explicit integration checks against a disposable Unix-socket Redis server.

This is not production Kvrocks performance validation. Start a dedicated test
server at /tmp/plum-271-test.sock; database 15 is cleared before each test.
Never point this suite at an application backend. Run with isolated Flask SQL
configuration as described in the reconciliation operational documentation.
"""

from copy import deepcopy
import os
import multiprocessing
import time
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from test.test_tag_reconciliation import snapshot

import redis
from meilisearch.models.document import Document

from app.utils.index_generations import (
    ACTIVE,
    CONTROL,
    GenerationClient,
    read_json,
    write_json,
)
from app.utils.index_reconciliation import (
    ReconciliationWorker,
    index_for,
    ingest_sources,
    queue_snapshot,
    delete_capture,
    reconciliation_status,
)

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
        self.meili.get_documents.side_effect = lambda query: SimpleNamespace(
            results=[Document({"id": uid}) for uid in sorted(self.documents)][
                query["offset"] : query["offset"] + query["limit"]
            ]
        )
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


class ReconciliationIntegrationTest(ReconciliationCase):
    """Exercise real command ordering, COW ownership, journals and publication."""

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
            self.raw.smembers(CONTROL + "candidates:" + worker.job["id"]), {"one"}
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
        frozen = snapshot([("a", "port:443", ["type:server"])])
        queue_snapshot(self.raw, frozen)
        worker = self.worker()
        worker.start()
        self.scan(worker)
        ingest_sources(self.raw, [source("two")], frozen)
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
        """The failure checkpoint must persist the snapshot with compact metadata."""
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
        job = read_json(self.raw, "job")
        self.assertEqual(job["phase"], "failed")
        inputs = read_json(self.raw, "g:" + job["id"] + ":inputs")
        self.assertEqual(inputs["snapshot"], self.first)
        self.worker().run()
        self.assertEqual(read_json(self.raw, "job")["phase"], "done")


if __name__ == "__main__":
    unittest.main()
