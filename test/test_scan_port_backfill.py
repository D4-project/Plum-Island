"""Immediate startup and durable checkpoint invariants for port backfill."""

from contextlib import nullcontext
import json
import unittest
from unittest.mock import Mock, patch

from app.utils.index_generations import ACTIVE, CONTROL
from app.utils.index_supervisor import IndexSupervisor
from app.utils.scan_port_backfill import (
    BACKFILL,
    BACKFILL_DONE,
    WINDOW_SECONDS,
    backfill_scan_ports,
)

from test.test_tag_reconciliation import snapshot


class BackfillStartupTest(unittest.TestCase):
    """Exercise startup with all existing detection rules already published."""

    def test_supervisor_starts_backfill_even_when_tags_are_up_to_date(self):
        """No rule change or manual reindex is required."""
        revision = {"revision": "current"}
        raw = Mock()
        raw.get.return_value = None
        state = {"job": {"phase": "done"}, "published": revision, "failure": {}}
        with patch("app.utils.index_supervisor.publish_controller_settings"), patch(
            "app.utils.index_supervisor.queue_snapshot"
        ), patch(
            "app.utils.index_supervisor.read_json",
            side_effect=lambda _r, key, _: state[key],
        ), patch(
            "app.utils.index_supervisor.file_lock", return_value=nullcontext()
        ), patch(
            "app.utils.index_supervisor.subprocess.Popen"
        ) as start:
            IndexSupervisor(raw, {}).tick(revision)
        start.assert_called_once()

    def test_stopped_work_keeps_frozen_window_and_resumes_from_anchor(self):
        """A later restart continues the same window and cursor."""
        rules = snapshot([])
        raw = Mock()
        state = {CONTROL + "published": json.dumps(rules), ACTIVE: "current"}
        raw.get.side_effect = state.get
        raw.set.side_effect = state.__setitem__
        committed = []

        def commit(_client, progress, rows, _summaries, offset):
            progress.update(anchor=rows[-1][0], score=rows[-1][1], offset=offset)
            state[CONTROL + BACKFILL] = json.dumps(progress)
            committed.extend(uid for uid, _ in rows)
            return True

        def read_page(_client, progress, _limit):
            if progress.get("anchor") == "old":
                return [], 0
            if progress.get("anchor") == "new":
                return [("old", 1000)], 1
            return [("new", 5000)], 1

        first_wait = iter([True, True, False])
        with patch(
            "app.utils.scan_port_backfill._next_page", side_effect=read_page
        ), patch(
            "app.utils.scan_port_backfill._build_summaries", return_value={}
        ), patch(
            "app.utils.scan_port_backfill._commit_page", side_effect=commit
        ):
            backfill_scan_ports(
                raw, Mock(), lambda _stop: next(first_wait), lambda: False
            )
            first_state = json.loads(state[CONTROL + BACKFILL])
            self.assertEqual(committed, ["new"])
            self.assertEqual(first_state["end"] - first_state["start"], WINDOW_SECONDS)
            self.assertNotIn(BACKFILL_DONE, state)
            backfill_scan_ports(raw, Mock(), lambda _stop: True, lambda: False)

        final_state = json.loads(state[CONTROL + BACKFILL])
        self.assertEqual(committed, ["new", "old"])
        self.assertEqual(final_state["end"], first_state["end"])
        self.assertEqual(state[BACKFILL_DONE], "1")
