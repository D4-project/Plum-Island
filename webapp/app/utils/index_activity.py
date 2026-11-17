"""Short-lived foreground leases and bounded, anonymized latency observations.

Telemetry fails open for readers. One heartbeat thread per web process renews
its live leases; an expired lease cannot keep indexing paused after a crash.
"""

from collections import OrderedDict
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import json
import threading
import time
from uuid import uuid4

import redis
from flask import has_request_context, request as flask_request
from redis.backoff import NoBackoff
from redis.retry import Retry

from app.utils.index_generations import CONTROL, pinned_read
from app.utils.tag_reconciliation import fingerprint

ACTIVITY = CONTROL + "activity:"
PACING = CONTROL + "pacing"
LEASE_SECONDS = 30
HEARTBEAT_SECONDS = 5
SAMPLE_LIMIT = 256
FOREGROUND_SCOPE = ContextVar("plum_index_foreground_scope", default=None)


def request_signature(request):
    """Compare equivalent first-page requests without storing queries or IPs."""
    if request.endpoint not in {"KVSearchView.query", "DiscoveryApi.search"}:
        return None
    data = request.get_json(silent=True) if request.is_json else request.args
    data = data or {}
    if not isinstance(data, Mapping):
        return None
    if data.get("cursor") or data.get("search_id") or data.get("cursor_ts"):
        return None
    parameters = {
        key: str(data.get(key) or "")
        for key in ("query", "from_ts", "to_ts", "limit", "window_days")
    }
    if any(len(value) > 4096 for value in parameters.values()):
        return None
    return fingerprint({"endpoint": request.endpoint, "parameters": parameters})


@dataclass
class ActivityLease:
    """One foreground operation, released even when the operation fails."""

    monitor: object
    kind: str
    signature: str | None = None
    token: str = field(default_factory=lambda: uuid4().hex)
    started: float = field(default_factory=time.monotonic)
    baseline: bool = False

    def finish(self):
        """Release activity and record a successful comparable timing sample."""
        self.monitor.finish(self)


class ActivityMonitor:
    """Share a connection pool and heartbeat across requests in this process."""

    def __init__(self, raw):
        self.raw = raw
        self.leases = {}
        self.lock = threading.Lock()
        self.thread = None

    def begin(self, kind="search", signature=None):
        """Register priority before a request reaches either search backend."""
        lease = ActivityLease(self, kind, signature)
        now = time.time()
        try:
            pipe = self.raw.pipeline(transaction=False)
            pipe.get(PACING)
            pipe.zadd(ACTIVITY + kind, {lease.token: now + LEASE_SECONDS})
            pipe.set(ACTIVITY + "last", str(now))
            values = pipe.execute()
            state = json.loads(values[0]) if values[0] else {}
            if not isinstance(state, dict):
                state = {"mode": "unknown"}
            lease.baseline = state.get("mode", "stopped") in {
                "stopped",
                "foreground",
                "quiet",
            }
        except (redis.RedisError, ValueError, TypeError):
            return None
        with self.lock:
            self.leases[lease.token] = lease
            if self.thread is None:
                self.thread = threading.Thread(target=self._renew, daemon=True)
                self.thread.start()
        return lease

    def finish(self, lease):
        """Release first, then retain only bounded anonymous timing data."""
        elapsed = time.monotonic() - lease.started
        with self.lock:
            if self.leases.pop(lease.token, None) is None:
                return
        # Heartbeat renewals hold the lock until their write finishes. Once
        # removed above, this lease cannot be resurrected; unrelated requests
        # need not wait for the following telemetry I/O.
        try:
            pipe = self.raw.pipeline(transaction=False)
            pipe.zrem(ACTIVITY + lease.kind, lease.token)
            pipe.set(ACTIVITY + "last", str(time.time()))
            if lease.signature:
                pipe.rpush(
                    ACTIVITY + "samples",
                    json.dumps(
                        {
                            "id": lease.token,
                            "signature": lease.signature,
                            "seconds": elapsed,
                            "baseline": lease.baseline,
                        }
                    ),
                )
                pipe.ltrim(ACTIVITY + "samples", -SAMPLE_LIMIT, -1)
            pipe.execute()
        except redis.RedisError:
            pass

    def _renew(self):
        """Expired process leases self-heal; never resurrect a completed lease."""
        while True:
            time.sleep(HEARTBEAT_SECONDS)
            with self.lock:
                if not self.leases:
                    self.thread = None
                    return
                try:
                    pipe = self.raw.pipeline(transaction=False)
                    for lease in self.leases.values():
                        pipe.zadd(
                            ACTIVITY + lease.kind,
                            {
                                lease.token: time.time() + LEASE_SECONDS,
                            },
                        )
                    pipe.execute()
                except redis.RedisError:
                    pass


_MONITORS = OrderedDict()
_MONITORS_LOCK = threading.Lock()


def monitor_for(config):
    """Use small telemetry timeouts; indexing coordination cannot break search."""
    if not config.get("TAG_RECONCILIATION_ENABLED", True):
        return None
    if not config.get("KVROCKS_HOST") or not config.get("KVROCKS_PORT"):
        return None
    endpoint = (config["KVROCKS_HOST"], config["KVROCKS_PORT"])
    with _MONITORS_LOCK:
        if endpoint not in _MONITORS:
            _MONITORS[endpoint] = ActivityMonitor(
                redis.Redis(
                    host=endpoint[0],
                    port=endpoint[1],
                    decode_responses=True,
                    socket_timeout=0.1,
                    socket_connect_timeout=0.1,
                    retry=Retry(NoBackoff(), 0),
                )
            )
        return _MONITORS[endpoint]


@contextmanager
def foreground_activity(config, kind="search", signature=None):
    """Prioritize one reader or ingestion task without changing its semantics."""
    existing = FOREGROUND_SCOPE.get()
    if existing is not None:
        yield existing
        return
    monitor = monitor_for(config)
    lease = monitor.begin(kind, signature) if monitor else None
    token = FOREGROUND_SCOPE.set(lease)
    try:
        yield lease
    except BaseException:
        if lease:
            lease.signature = None
        raise
    finally:
        FOREGROUND_SCOPE.reset(token)
        if lease:
            lease.finish()


def prioritized_search(function):
    """Register activity inside an authorized operation, after access checks."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        from app import app  # pylint: disable=import-outside-toplevel

        signature = request_signature(flask_request) if has_request_context() else None
        with foreground_activity(app.config, signature=signature) as lease:
            result = function(*args, **kwargs)
            if lease and isinstance(result, dict) and result.get("status") is False:
                lease.signature = None
            return result

    return wrapped


def prioritized_read(function):
    """Pin an export/report generation and give its work foreground priority."""
    pinned = pinned_read(function)

    @wraps(function)
    def wrapped(*args, **kwargs):
        from app import app  # pylint: disable=import-outside-toplevel

        with foreground_activity(app.config):
            return pinned(*args, **kwargs)

    return wrapped


def prioritized_ingestion(function):
    """Let the scheduler's durable export pipeline run ahead of reconciliation."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        from app import app  # pylint: disable=import-outside-toplevel

        with foreground_activity(app.config, "ingestion"):
            return function(*args, **kwargs)

    return wrapped


def pacing_status(raw):
    """Read public operational pacing data, excluding query fingerprints."""
    value = raw.get(PACING)
    return json.loads(value) if value else {}
