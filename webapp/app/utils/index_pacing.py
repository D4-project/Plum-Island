"""Cooperative resource control around the unchanged reconciliation state machine.

This operational wrapper does not change rule/parser semantics or their code
fingerprint. Existing frozen jobs can resume their planning cursor after upgrade.
"""

from collections import OrderedDict, deque
import json
import statistics
import time
import logging
import os

import redis

from app.utils.index_activity import ACTIVITY, PACING, SAMPLE_LIMIT, SAMPLES
from app.utils.index_generations import ACTIVE, CONTROL, GenerationClient, write_json
from app.utils.index_retry import retry_delay, transient_error
from app.utils.index_reconciliation import (
    ReconciliationWorker,
    SnapshotInvalid,
    write_barrier,
)
from app.utils.index_sources import ExcludedSource, SourceDocuments
from app.utils.index_source_recovery import SOURCE_CONFLICT, orphan_exclusion_metadata

logger = logging.getLogger(__name__)


class LoadController:  # pylint: disable=too-many-instance-attributes
    """Pause for foreground work; use measured latency to extend quiet time."""

    def __init__(self, raw, config):
        self.raw = raw
        self.target = max(
            0.0, float(config.get("TAG_RECONCILIATION_LATENCY_BUDGET", 0.1))
        )
        self.quiet_seconds = max(
            0.0, float(config.get("TAG_RECONCILIATION_QUIET_SECONDS", 2))
        )
        self.idle_seconds = max(
            self.quiet_seconds, float(config.get("TAG_RECONCILIATION_IDLE_SECONDS", 15))
        )
        self.max_planning = max(
            1, int(config.get("TAG_RECONCILIATION_PLANNING_BATCH_SIZE", 1000))
        )
        self.min_planning = min(
            self.max_planning,
            max(1, int(config.get("TAG_RECONCILIATION_MIN_PLANNING_BATCH_SIZE", 25))),
        )
        self.planning_sizes = {
            "kvrocks": self.max_planning,
            "meili": max(self.min_planning, min(250, self.max_planning)),
        }
        self.max_unit_seconds = max(
            0.001, float(config.get("TAG_RECONCILIATION_UNIT_SECONDS", 0.05))
        )
        self.mode = "limited"
        self.factor = 1.0
        self.idle_periods = 0
        self.degradation = None
        self.baselines = OrderedDict()
        self.seen = deque(maxlen=SAMPLE_LIMIT)
        self.last_metrics = 0.0
        self.last_publish = 0.0
        self.last_mode = None
        self.active = 0
        self.comparisons = 0
        self.candidates = None
        self.excluded = 0

    def observe_latency(self):
        """Compare only matching first-page requests with uncontended baselines."""
        if time.monotonic() - self.last_metrics < 1:
            return
        self.last_metrics = time.monotonic()
        seen = set(self.seen)
        for serialized in self.raw.lrange(SAMPLES, -SAMPLE_LIMIT, -1):
            sample = json.loads(serialized)
            if sample["id"] in seen:
                continue
            self.seen.append(sample["id"])
            key = sample["signature"]
            if sample["baseline"]:
                self.baselines.setdefault(key, deque(maxlen=20)).append(
                    sample["seconds"]
                )
                self.baselines.move_to_end(key)
                if len(self.baselines) > 128:
                    self.baselines.popitem(last=False)
            elif len(self.baselines.get(key, ())) >= 3:
                baseline = statistics.median(self.baselines[key])
                if baseline <= 0:
                    continue
                self.degradation = sample["seconds"] / baseline - 1
                self.comparisons += 1
                if self.degradation > self.target:
                    self.factor = min(16.0, self.factor * 2)
                else:
                    self.factor = max(1.0, self.factor / 2)

    def publish(self, force=False):
        """Publish pacing separately from immutable rule and progress records."""
        now = time.monotonic()
        if not force and self.mode == self.last_mode and now - self.last_publish < 1:
            return
        self.raw.set(
            PACING,
            json.dumps(
                {
                    "mode": self.mode,
                    "heartbeat": time.time(),
                    "foreground_operations": self.active,
                    "latency_budget": self.target,
                    "observed_degradation": self.degradation,
                    "comparable_samples": self.comparisons,
                    "planning_batch": dict(self.planning_sizes),
                    "slowdown_factor": self.effective_factor,
                    "candidates": self.candidates,
                    "excluded_sources": self.excluded,
                }
            ),
        )
        self.last_publish = now
        self.last_mode = self.mode

    def ready(self):
        """Check leases before each unit, including between captures in a batch."""
        now = time.time()
        pipe = self.raw.pipeline(transaction=False)
        for kind in ("search", "ingestion"):
            pipe.zremrangebyscore(ACTIVITY + kind, "-inf", now)
            pipe.zcount(ACTIVITY + kind, now, "+inf")
        pipe.get(ACTIVITY + "last")
        results = pipe.execute()
        self.active = int(results[1]) + int(results[3])
        quiet = now - float(results[4] or 0)
        self.idle_periods = min(4, max(0, int((quiet - self.idle_seconds) // 60)))
        self.observe_latency()
        if self.active:
            self.mode = "foreground"
        elif quiet < min(self.idle_seconds, self.quiet_seconds * self.factor):
            self.mode = "quiet"
        else:
            self.mode = "idle_boost" if quiet >= self.idle_seconds else "limited"
        self.publish()
        return self.mode in {"idle_boost", "limited"}

    def wait(self, stopping):
        """Signals interrupt waiting within one short polling interval."""
        while not stopping():
            if self.ready():
                return True
            time.sleep(0.05)
        return False

    @property
    def effective_factor(self):
        """Recover idle throughput each quiet minute; retain pressure on return."""
        periods = self.idle_periods if self.mode == "idle_boost" else 0
        return max(1.0, self.factor / (2**periods))

    def planning_observed(self, backend, size, elapsed):
        """Bound the next planning read using the duration of the previous one."""
        if elapsed <= 0:
            return
        target = self.max_unit_seconds
        baselines = [
            statistics.median(values)
            for values in self.baselines.values()
            if len(values) >= 3
        ]
        if baselines:
            target = min(target, max(0.001, min(baselines) * self.target))
        target = max(0.001, target / self.effective_factor)
        estimate = int(size * target / elapsed)
        self.planning_sizes[backend] = max(
            self.min_planning, min(self.max_planning, estimate, size * 2)
        )


class PacedReconciliationWorker(ReconciliationWorker):
    """Keep frozen-job compatibility while changing only runtime work pacing."""

    def __init__(self, raw, meili, config):
        super().__init__(
            raw,
            SourceDocuments(meili),
            batch_size=config.get("TAG_RECONCILIATION_BATCH_SIZE", 25),
            pause_seconds=config.get("TAG_RECONCILIATION_PAUSE_SECONDS", 0.1),
        )
        self.load = LoadController(raw, config)

    def run(self):
        """Resume durable work after transport outages, with interruptible waits."""
        attempts = 0
        while not self.stopping:
            try:
                super().run()
            except BlockingIOError:
                # Another worker may take ownership while this one backs off.
                return
            except Exception as error:
                if not transient_error(error):
                    raise
                attempts += 1
                delay = retry_delay(attempts)
                if self._record_backend_retry(delay):
                    return
                logger.warning(
                    "Index worker backend unavailable (%s); retrying in %.0fs from saved checkpoint",
                    type(error).__name__,
                    delay,
                    exc_info=attempts == 1,
                )
                if not self._wait_backend_retry(delay):
                    self._record_backend_pause()
                    return
                # Always reload durable inputs, never advance a failed in-memory cursor.
                self.job = None
                self.plan = None
                self._inputs_saved = False
            else:
                if attempts:
                    logger.info(
                        "Index worker recovered after %s transport retry attempt(s)",
                        attempts,
                    )
                    try:
                        self.raw.delete(CONTROL + "failure")
                    except redis.RedisError:
                        pass
                return

    def _record_backend_retry(self, delay):
        """Status is best effort; never overwrite an acknowledged publication."""
        try:
            if self.job and self.raw.get(ACTIVE) == self.job["id"]:
                return True
            message = "Backend temporarily unavailable; automatically retrying from saved checkpoint. Active index retained."
            if self.job:
                self.checkpoint(
                    phase="retrying", message=message, retry_at=time.time() + delay
                )
                self.raw.delete(CONTROL + "failure")
            else:
                write_json(
                    self.raw,
                    "failure",
                    {
                        "phase": "retrying",
                        "message": message,
                        "retry_at": time.time() + delay,
                    },
                )
        except redis.RedisError:
            # If Kvrocks is unreachable, the last durable cursor remains authoritative.
            pass
        return False

    def _record_backend_pause(self):
        """Retain normal stop status when a stop interrupts retry backoff."""
        try:
            if self.job:
                if self.raw.get(ACTIVE) != self.job["id"]:
                    self.checkpoint(
                        phase="paused", message="Stopped after checkpoint", retry_at=0
                    )
            else:
                write_json(
                    self.raw,
                    "failure",
                    {
                        "phase": "paused",
                        "message": "Stopped before indexing started",
                        "retry_at": 0,
                    },
                )
        except redis.RedisError:
            pass

    def _wait_backend_retry(self, delay):
        """Wait outside publication barriers and react promptly to stop/parent exit."""
        deadline = time.monotonic() + delay
        while not self.stopping:
            parent = os.environ.get("PLUM_INDEX_PARENT_PID")
            if parent and os.getppid() != int(parent):
                self.stopping = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            time.sleep(min(0.5, remaining))
        return False

    def start(self):
        """Restore operational counters alongside the original frozen inputs."""
        started = super().start()
        if started:
            self.load.excluded = self.job.get("excluded_sources", 0)
        return started

    @property
    def pause_seconds(self):
        """Use short idle yields; measured slowdowns increase normal pacing."""
        if not hasattr(self, "load"):
            return self._base_pause
        pause = 0.01 if self.load.mode == "idle_boost" else self._base_pause
        return pause * self.load.effective_factor

    @pause_seconds.setter
    def pause_seconds(self, value):
        self._base_pause = value

    def prepare_candidates_batch(self):
        """Inventory IDs in independent, bounded batches; preserve saved cursors."""
        if not self.load.wait(lambda: self.stopping):
            return
        if self.job["phase"] != "planning":
            self.checkpoint(phase="planning", total=None)
        sources = self.job.get("candidate_sources") or ()
        position = self.job.get("candidate_source", 0)
        backend = (
            "meili"
            if position < len(sources) and sources[position] == "@meili"
            else "kvrocks"
        )
        original = self.batch_size
        self.batch_size = self.load.planning_sizes[backend]
        started = time.monotonic()
        try:
            super().prepare_candidates_batch()
            self.load.candidates = self.raw.scard(
                CONTROL + "candidates:" + self.job["id"]
            )
        finally:
            self.load.planning_observed(
                backend, self.batch_size, time.monotonic() - started
            )
            self.batch_size = original

    def scan_batch(self):
        """A stop while waiting leaves the durable pending UID list untouched."""
        if self.load.wait(lambda: self.stopping):
            super().scan_batch()

    def process_uid(self, uid):
        """Yield between captures, then finish a claimed unit even on SIGTERM."""
        self.load.wait(lambda: self.stopping)
        try:
            super().process_uid(uid)
        except ExcludedSource as error:
            self.exclude_source(uid, error.address)

    def exclude_source(self, uid, address):
        """Count unindexed exclusions, preserving detached historical dates."""
        with write_barrier(background=True):
            metadata = orphan_exclusion_metadata(self.raw, self.job, uid, address)
            if metadata is None:
                raise SnapshotInvalid(SOURCE_CONFLICT)
            if metadata:
                target = GenerationClient(self.raw, self.job["id"], writable=True)
                target.hset(f"doc:{uid}", mapping=metadata)
            key = CONTROL + "g:" + self.job["id"] + ":excluded_sources"
            pipe = self.raw.pipeline(transaction=True)
            pipe.sadd(key, uid)
            pipe.sadd(CONTROL + "processed:" + self.job["id"], uid)
            pipe.execute()
            self.load.excluded = self.raw.scard(key)
            self.job["excluded_sources"] = self.load.excluded

    def replay_batch(self):
        """Check foreground priority between individual journal entries."""
        original = self.batch_size
        self.batch_size = 1
        try:
            for _ in range(original):
                if not self.load.wait(lambda: self.stopping):
                    return False
                if super().replay_batch():
                    self._stopped()
                    return True
            return False
        finally:
            self.batch_size = original

    def checkpoint(self, **changes):
        """Publish stopped activity while still holding the worker ownership lock."""
        super().checkpoint(**changes)
        if changes.get("phase") in {"paused", "failed", "blocked"}:
            self._stopped()

    def _stopped(self):
        """Telemetry errors cannot mask the actual job's final status."""
        self.load.mode = "stopped"
        try:
            self.load.publish(force=True)
        except redis.RedisError:
            pass
