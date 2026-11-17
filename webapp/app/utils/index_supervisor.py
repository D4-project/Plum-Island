"""Scheduler-owned subprocess lifecycle; no heavy indexing in scheduler threads."""

import os
from pathlib import Path
import subprocess
import sys
import time

from app.utils.index_generations import CONTROL, file_lock, read_json
from app.utils.index_reconciliation import (
    processing_revision,
    queue_snapshot,
    state_directory,
)


class IndexSupervisor:
    """Own only processes we launched; never signal a PID read from storage."""

    def __init__(self, raw, config):
        self.raw = raw
        self.config = config
        self.process = None
        self.stopped = False

    def stop(self):
        """Ask our child to finish its current unit and save a checkpoint."""
        self.stopped = True
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()

    def tick(self, snapshot):
        """Reconcile committed desired state, reap a child and start pending work."""
        queue_snapshot(self.raw, snapshot)
        if self.process is not None:
            if self.process.poll() is None:
                if not self.config.get("TAG_RECONCILIATION_ENABLED", True):
                    self.process.terminate()
                return
            self.process = None
        if self.stopped or not self.config.get("TAG_RECONCILIATION_ENABLED", True):
            return
        job = read_json(self.raw, "job", {})
        failure = read_json(self.raw, "failure", {})
        published = read_json(self.raw, "published", {})
        pending = snapshot.get("revision") != published.get("revision")
        pending = pending or self.raw.get(CONTROL + "force_full")
        if (
            job.get("phase") == "blocked"
            and snapshot.get("revision") == processing_revision(job)
            and not self.raw.get(CONTROL + "force_full")
        ):
            return
        if not pending and job.get("phase", "done") == "done":
            return
        if (
            max(float(job.get("retry_at") or 0), float(failure.get("retry_at") or 0))
            > time.time()
        ):
            return
        try:
            with file_lock(state_directory() / "worker.lock", blocking=False):
                pass
        except BlockingIOError:
            return
        root = Path(__file__).resolve().parents[3]
        environment = dict(os.environ)
        environment.pop("WERKZEUG_RUN_MAIN", None)
        environment["PLUM_INDEX_PARENT_PID"] = str(os.getpid())
        self.process = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, str(root / "tools" / "reconcile_index.py")],
            cwd=str(root / "webapp"),
            env=environment,
        )
