"""Frozen rule planning, dependency removal and truthful coverage checks."""

from copy import deepcopy
from contextlib import nullcontext
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from app.utils.tag_reconciliation import RulePlan, fingerprint, rule_snapshot
from app.utils.index_reconciliation import ReconciliationWorker, coverage_profile
from app.utils.index_supervisor import IndexSupervisor


def snapshot(rules, headers=None):
    """Build actual snapshots without querying the application database."""
    records = [
        SimpleNamespace(uuid=key, query=query, tags=tags, active=True)
        for key, query, tags in rules
    ]
    collection = [
        SimpleNamespace(header_name=key, collect_value=value)
        for key, value in (headers or {}).items()
    ]
    return rule_snapshot(records, {}, collection)


class RulePlanTest(unittest.TestCase):
    """Changing one rule must not destroy other producers or invent matches."""

    def test_unchanged_negative_rules_are_not_evaluated(self):
        """Unchanged negative rules are not evaluated."""
        state = snapshot(
            [("a", "port:443", ["proto:https"]), ("b", "port:22", ["proto:ssh"])]
        )
        plan = RulePlan(state, state)
        with patch(
            "app.utils.tag_reconciliation.document_matches_criteria_groups"
        ) as match:
            tags, contributions = plan.evaluate(
                {"port": ["443"]}, {"a": ["proto:https"]}
            )
        match.assert_not_called()
        self.assertEqual(tags, ["proto:https"])
        self.assertEqual(contributions, {"a": ["proto:https"]})

    def test_retag_reads_full_nse_report_only_for_a_rule_being_evaluated(self):
        """Access full reports only for evaluations that depend on NSE text."""
        query = 'service:rdp AND nse.body:rdp.lk:"target_name: BETZDORF-WASSER"'
        state = snapshot([("a", query, ["site:betzdorf-wasser"])])
        source = {
            "body": {
                "ports": [
                    {
                        "scripts": [
                            {"id": "rdp", "output": "target_name: BETZDORF-WASSER"}
                        ]
                    }
                ]
            }
        }
        for previous, should_read in ((snapshot([]), True), (state, False)):
            with self.subTest(should_read=should_read):
                raw = Mock()
                raw.sismember.return_value = False
                meili = Mock()
                meili.get_document.return_value = source
                worker = ReconciliationWorker(raw, meili)
                worker.plan = RulePlan(state, previous)
                worker.job = {
                    "id": "job",
                    "parent": "parent",
                    "full": False,
                    "snapshot": state,
                }
                client = Mock()
                client.get.side_effect = [
                    "coverage-id",
                    "{}" if should_read else '{"a": ["site:betzdorf-wasser"]}',
                ]
                module = "app.utils.index_reconciliation"
                with (
                    patch(f"{module}.GenerationClient", return_value=client),
                    patch(f"{module}.read_json", return_value=coverage_profile(state)),
                    patch(f"{module}.load_document", return_value={"service": ["rdp"]}),
                    patch(f"{module}.write_barrier", return_value=nullcontext()),
                    patch(f"{module}.save_document") as save,
                ):
                    worker.process_uid("one")
                if should_read:
                    meili.get_document.assert_called_once_with("one")
                else:
                    meili.get_document.assert_not_called()
                self.assertFalse(save.call_args.kwargs["full"])
                self.assertEqual(save.call_args.args[1]["tag"], ["site:betzdorf-wasser"])

    def test_removed_producer_and_negative_dependency(self):
        """Removed producer and negative dependency."""
        before = snapshot(
            [
                ("a", "port:443", ["proto:https"]),
                ("b", "port:443 AND NOT tag:proto:https", ["type:server"]),
            ]
        )
        after = snapshot([("b", "port:443 AND NOT tag:proto:https", ["type:server"])])
        plan = RulePlan(after, before)
        tags, _ = plan.evaluate({"port": ["443"]}, {"a": ["proto:https"]})
        self.assertEqual(tags, ["type:server"])

    def test_tag_removed_from_modified_producer_rechecks_dependent(self):
        """Tag removed from modified producer rechecks dependent."""
        before = snapshot(
            [
                ("a", "port:443", ["proto:https"]),
                ("b", "port:443 AND tag:proto:https", ["type:server"]),
            ]
        )
        after = snapshot(
            [
                ("a", "port:443", ["proto:http"]),
                ("b", "port:443 AND tag:proto:https", ["type:server"]),
            ]
        )
        tags, _ = RulePlan(after, before).evaluate(
            {"port": ["443"]}, {"a": ["proto:https"], "b": ["type:server"]}
        )
        self.assertEqual(tags, ["proto:http"])

    def test_shared_tag_survives_rule_deletion(self):
        """Shared tag survives rule deletion."""
        before = snapshot(
            [("a", "port:443", ["type:server"]), ("b", "port:443", ["type:server"])]
        )
        after = snapshot([("b", "port:443", ["type:server"])])
        tags, _ = RulePlan(after, before).evaluate(
            {"port": ["443"]}, {"a": ["type:server"], "b": ["type:server"]}
        )
        self.assertEqual(tags, ["type:server"])

    def test_unknown_coverage_and_header_value_require_reparse(self):
        """Unknown coverage and header value require reparse."""
        state = snapshot(
            [("a", "http_headval:x-powered-by.lk:php", ["lang:php"])],
            {"x-powered-by": True},
        )
        plan = RulePlan(state)
        self.assertFalse(plan.covered(None))
        coverage = {"parser": deepcopy(state["parser"]), "code": state["code"]}
        self.assertTrue(plan.covered(coverage))
        coverage["parser"]["HTTP_HEADER_COLLECTION"]["x-powered-by"] = False
        self.assertFalse(plan.covered(coverage))

    def test_cycle_is_rejected_before_publication(self):
        """Cycle is rejected before publication."""
        state = snapshot([("a", "port:443 AND tag:type:server", ["type:server"])])
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            RulePlan(state)

    def test_snapshot_ignores_rule_order_and_cosmetic_metadata(self):
        """Snapshot ignores rule order and cosmetic metadata."""
        rules = [("a", "port:443", ["proto:https"]), ("b", "port:22", ["proto:ssh"])]
        self.assertEqual(
            snapshot(rules)["revision"], snapshot(list(reversed(rules)))["revision"]
        )
        self.assertNotEqual(fingerprint(["a|b", "c"]), fingerprint(["a", "b|c"]))


class SupervisorTest(unittest.TestCase):
    """Scheduler must not block waiting for its index child."""

    def test_stop_signals_only_its_child_without_waiting(self):
        """Stop signals only its child without waiting."""
        supervisor = IndexSupervisor(Mock(), {})
        supervisor.process = Mock()
        supervisor.process.poll.return_value = None
        supervisor.stop()
        supervisor.process.terminate.assert_called_once()
        supervisor.process.wait.assert_not_called()

    def test_unchanged_blocked_inline_snapshot_is_not_restarted(self):
        """Old jobs expose their frozen revision inside snapshot, not metadata."""
        raw = Mock()
        raw.get.return_value = None
        supervisor = IndexSupervisor(raw, {})
        state = {
            "job": {"phase": "blocked", "snapshot": {"revision": "current"}},
            "failure": {},
            "published": {},
        }
        with patch("app.utils.index_supervisor.queue_snapshot"), patch(
            "app.utils.index_supervisor.read_json",
            side_effect=lambda _raw, key, _default: state[key],
        ), patch("app.utils.index_supervisor.subprocess.Popen") as process:
            supervisor.tick({"revision": "current"})
        process.assert_not_called()

    def test_full_rebuild_bypasses_old_job_and_failure_retry_deadlines(self):
        """Explicit recovery starts despite the superseded parser failure cooldown."""
        for forced in (False, True):
            with self.subTest(forced=forced):
                raw = Mock()
                raw.get.return_value = "1" if forced else None
                supervisor = IndexSupervisor(raw, {})
                deadline = time.time() + 3600
                state = {
                    "job": {
                        "phase": "blocked",
                        "snapshot_revision": "current",
                        "retry_at": deadline,
                    },
                    "failure": {"retry_at": deadline},
                    "published": {"revision": "old"},
                }
                with patch("app.utils.index_supervisor.queue_snapshot"), patch(
                    "app.utils.index_supervisor.read_json",
                    side_effect=lambda _raw, key, _default, _state=state: _state[key],
                ), patch(
                    "app.utils.index_supervisor.file_lock", return_value=nullcontext()
                ), patch(
                    "app.utils.index_supervisor.subprocess.Popen"
                ) as process:
                    supervisor.tick({"revision": "current"})
                self.assertEqual(process.call_count, int(forced))

    def test_tick_starts_only_one_child_without_werkzeug_scheduler_flag(self):
        """Launching the child cannot recursively import another scheduler."""
        supervisor = IndexSupervisor(Mock(), {})
        state = {"job": {}, "failure": {}, "published": {"revision": "old"}}
        with patch("app.utils.index_supervisor.queue_snapshot"), patch(
            "app.utils.index_supervisor.read_json",
            side_effect=lambda _raw, key, _default: state[key],
        ), patch(
            "app.utils.index_supervisor.file_lock", return_value=nullcontext()
        ), patch(
            "app.utils.index_supervisor.subprocess.Popen"
        ) as process, patch.dict(
            os.environ, {"WERKZEUG_RUN_MAIN": "true"}
        ):
            process.return_value.poll.return_value = None
            supervisor.tick({"revision": "new"})
            supervisor.tick({"revision": "newer"})
            process.assert_called_once()
            self.assertNotIn("WERKZEUG_RUN_MAIN", process.call_args.kwargs["env"])
            self.assertTrue(
                process.call_args.args[0][-1].endswith("tools/reconcile_index.py")
            )
            process.return_value.wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
