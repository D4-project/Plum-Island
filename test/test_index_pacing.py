"""Foreground priority, idle acceleration and comparable latency feedback."""

import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import redis

from app.utils.index_activity import (
    ActivityMonitor,
    foreground_activity,
    request_signature,
)
from app.utils.index_pacing import LoadController


class LoadControllerTest(unittest.TestCase):
    """The same state machine must yield for users and accelerate when quiet."""

    def setUp(self):
        self.raw = Mock()
        self.raw.lrange.return_value = []
        self.controller = LoadController(self.raw, {})

    def test_readers_and_ingestion_take_priority_over_idle_boost(self):
        """An active lease always wins even after a long quiet interval."""
        for readers, ingestion in ((1, 0), (0, 1)):
            with self.subTest(readers=readers, ingestion=ingestion):
                self.raw.pipeline.return_value.execute.return_value = [
                    0,
                    readers,
                    0,
                    ingestion,
                    "1",
                ]
                with patch("app.utils.index_pacing.time.time", return_value=100):
                    self.assertFalse(self.controller.ready())
                self.assertEqual(self.controller.mode, "foreground")

    def test_recent_activity_waits_then_idle_work_accelerates(self):
        """Quiet-time protection releases automatically after activity stops."""
        with patch("app.utils.index_pacing.time.time", return_value=100):
            self.raw.pipeline.return_value.execute.return_value = [0, 0, 0, 0, "99"]
            self.assertFalse(self.controller.ready())
            self.assertEqual(self.controller.mode, "quiet")
            self.raw.pipeline.return_value.execute.return_value = [0, 0, 0, 0, "95"]
            self.assertTrue(self.controller.ready())
            self.assertEqual(self.controller.mode, "limited")
            self.raw.pipeline.return_value.execute.return_value = [0, 0, 0, 0, "80"]
            self.assertTrue(self.controller.ready())
            self.assertEqual(self.controller.mode, "idle_boost")

    def test_ten_percent_budget_uses_matching_baselines_only(self):
        """A slow unrelated query cannot be compared with a cheap query baseline."""
        samples = [
            {"id": str(index), "signature": "query-a", "seconds": 1, "baseline": True}
            for index in range(3)
        ]
        samples.append(
            {"id": "other", "signature": "query-b", "seconds": 10, "baseline": False}
        )
        self.raw.lrange.return_value = [json.dumps(item) for item in samples]
        self.controller.observe_latency()
        self.assertIsNone(self.controller.degradation)
        self.assertEqual(self.controller.factor, 1)
        samples.append(
            {"id": "slow", "signature": "query-a", "seconds": 1.2, "baseline": False}
        )
        self.raw.lrange.return_value = [json.dumps(item) for item in samples]
        self.controller.last_metrics = 0
        self.controller.observe_latency()
        self.assertAlmostEqual(self.controller.degradation, 0.2)
        self.assertEqual(self.controller.factor, 2)
        self.controller.last_metrics = 0
        self.controller.observe_latency()
        self.assertEqual(self.controller.comparisons, 1)
        self.assertEqual(self.controller.factor, 2)

    def test_slow_planning_reads_reduce_the_next_unit(self):
        """A large batch does not remain large when the backend is slow."""
        self.controller.planning_observed("meili", 1000, 0.5)
        self.assertEqual(self.controller.planning_sizes["meili"], 100)
        self.controller.planning_observed("meili", 100, 0.001)
        self.assertEqual(self.controller.planning_sizes["meili"], 200)

    def test_stop_interrupts_foreground_wait(self):
        """No polling or background work after the stop flag is raised."""
        self.assertFalse(self.controller.wait(lambda: True))
        self.raw.pipeline.assert_not_called()


class ActivityMonitorTest(unittest.TestCase):
    """Optional activity telemetry cannot change request results or leak queries."""

    def test_backend_failure_does_not_break_foreground_request(self):
        """Prioritization is best effort when the backend is unreachable."""
        raw = Mock()
        raw.pipeline.return_value.execute.side_effect = redis.ConnectionError()
        self.assertIsNone(ActivityMonitor(raw).begin())

    def test_signature_is_specific_anonymous_and_skips_continuations(self):
        """Different queries/windows cannot silently share timing baselines."""
        request = SimpleNamespace(
            endpoint="KVSearchView.query", is_json=False, args={"query": "port:443"}
        )
        first = request_signature(request)
        self.assertEqual(len(first), 128)
        self.assertNotIn("port", first)
        request.args["query"] = "port:22"
        self.assertNotEqual(first, request_signature(request))
        request.args["search_id"] = "continuation"
        self.assertIsNone(request_signature(request))

    def test_invalid_json_does_not_fail_inside_telemetry(self):
        """Endpoint validation retains ownership of invalid request payloads."""
        request = SimpleNamespace(
            endpoint="KVSearchView.query", is_json=True, get_json=lambda **_kwargs: [1]
        )
        self.assertIsNone(request_signature(request))

    def test_failed_work_does_not_record_a_successful_latency(self):
        """Backend errors must not establish an artificially cheap baseline."""
        monitor = Mock()
        lease = monitor.begin.return_value
        lease.signature = "query"
        with patch("app.utils.index_activity.monitor_for", return_value=monitor):
            with self.assertRaises(ValueError):
                with foreground_activity({}, signature="query"):
                    raise ValueError("search failed")
        self.assertIsNone(lease.signature)
        lease.finish.assert_called_once()

    def test_nested_report_searches_share_one_foreground_lease(self):
        """Nested read helpers must not add one heartbeat per backend call."""
        monitor = Mock()
        with patch("app.utils.index_activity.monitor_for", return_value=monitor):
            with foreground_activity({}) as outer:
                with foreground_activity({}) as inner:
                    self.assertIs(outer, inner)
        monitor.begin.assert_called_once()
        outer.finish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
