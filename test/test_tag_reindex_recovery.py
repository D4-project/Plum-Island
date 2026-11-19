#!/usr/bin/env python3
"""Regression coverage for interrupted tag-reindex detection."""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase, main

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "webapp"))

from app.views import _tag_reindex_is_stale  # pylint: disable=wrong-import-position


class TagReindexRecoveryTest(TestCase):
    """Verify dead owners and stale heartbeats are recoverable."""

    def test_dead_owner_is_stale_immediately(self):
        self.assertTrue(_tag_reindex_is_stale({"status": "running", "pid": 999999999}))

    def test_recent_heartbeat_from_current_process_is_not_stale(self):
        heartbeat = datetime.now(timezone.utc).isoformat()
        self.assertFalse(
            _tag_reindex_is_stale(
                {"status": "running", "pid": os.getpid(), "heartbeat_at": heartbeat}
            )
        )

    def test_old_heartbeat_is_stale(self):
        heartbeat = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.assertTrue(
            _tag_reindex_is_stale(
                {"status": "running", "pid": os.getpid(), "heartbeat_at": heartbeat}
            )
        )


if __name__ == "__main__":
    main()
