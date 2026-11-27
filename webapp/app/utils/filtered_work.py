"""Temporary Kvrocks state for filtered scan preparation."""

import hashlib
import json

from app.utils.index_generations import CONTROL

SCAN_BATCH_SIZE = 500


def _prefix(cycle_id, revision):
    return f"{CONTROL}filtered:{cycle_id}:{revision}"


def _keys(cycle_id, revision):
    prefix = _prefix(cycle_id, revision)
    return {
        "prefix": prefix,
        "meta": prefix + ":meta",
        "candidates": prefix + ":candidates",
        "groups": prefix + ":groups",
    }


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _group_id(metadata):
    return hashlib.sha256(_canonical(metadata).encode()).hexdigest()[:24]


class FilteredWorkStore:  # pylint: disable=too-many-public-methods
    """Collect, group and consume filtered scan work without SQLite rows."""

    def __init__(self, raw, cycle_id, revision):
        self.raw = raw
        self.cycle_id = int(cycle_id)
        self.revision = int(revision)
        self.keys = _keys(cycle_id, revision)

    def metadata(self):
        """Return persisted cycle metadata."""
        return self.raw.hgetall(self.keys["meta"])

    def begin(self, from_ts, to_ts):
        """Create metadata once while preserving an interrupted checkpoint."""
        pipe = self.raw.pipeline(transaction=True)
        pipe.hset(
            self.keys["meta"],
            mapping={
                "cycle_id": self.cycle_id,
                "revision": self.revision,
                "from_ts": int(from_ts),
                "to_ts": int(to_ts),
            },
        )
        pipe.hsetnx(self.keys["meta"], "stage", "collecting")
        pipe.hsetnx(self.keys["meta"], "checked", 0)
        pipe.execute()

    def reset(self):
        """Delete one cycle's bounded temporary state."""
        group_ids = tuple(self.raw.hkeys(self.keys["groups"]))
        keys = [self.keys["meta"], self.keys["candidates"], self.keys["groups"]]
        keys.extend(self.group_key(group_id) for group_id in group_ids)
        if keys:
            self.raw.delete(*keys)

    def checkpoint(self):
        """Return newest-first search cursor, when collection already started."""
        meta = self.metadata()
        if not meta.get("cursor_score"):
            return None
        return float(meta["cursor_score"]), int(meta.get("cursor_offset", 0))

    def add_candidates(  # pylint: disable=too-many-locals
        self, candidates, checked, cursor
    ):
        """Merge one search page, then publish its replay-safe cursor."""
        merged = {}
        for target_id, kind, value, ports, family in candidates:
            identity = _canonical(
                {
                    "target_id": int(target_id),
                    "kind": kind,
                    "value": value,
                    "family": family,
                }
            )
            merged.setdefault(identity, set()).update(int(port) for port in ports)
        if merged:
            pipe = self.raw.pipeline(transaction=False)
            for identity in merged:
                pipe.hget(self.keys["candidates"], identity)
            previous = pipe.execute()
            mapping = {}
            for (identity, ports), stored in zip(merged.items(), previous):
                if stored:
                    ports.update(int(port) for port in stored.split(",") if port)
                mapping[identity] = ",".join(map(str, sorted(ports)))
            self.raw.hset(self.keys["candidates"], mapping=mapping)
        score, offset = cursor
        self.raw.hset(
            self.keys["meta"],
            mapping={
                "checked": int(checked),
                "retained": self.raw.hlen(self.keys["candidates"]),
                "cursor_score": score,
                "cursor_offset": int(offset),
            },
        )

    def finish_collection(self):  # pylint: disable=too-many-locals
        """Build deterministic work groups from merged candidates."""
        self.raw.hset(self.keys["meta"], "stage", "grouping")
        cursor = 0
        while True:
            cursor, records = self.raw.hscan(
                self.keys["candidates"], cursor=cursor, count=SCAN_BATCH_SIZE
            )
            pipe = self.raw.pipeline(transaction=False)
            groups = {}
            for identity, ports in records.items():
                candidate = json.loads(identity)
                metadata = {
                    "kind": candidate["kind"],
                    "family": candidate.get("family"),
                    "ports": ports,
                }
                group_id = _group_id(metadata)
                groups[group_id] = _canonical(metadata)
                pipe.zadd(self.group_key(group_id), {identity: 0})
            if groups:
                pipe.hset(self.keys["groups"], mapping=groups)
            pipe.execute()
            if not cursor:
                break
        self.raw.hset(
            self.keys["meta"],
            mapping={
                "stage": "ready",
                "retained": self.raw.hlen(self.keys["candidates"]),
            },
        )

    def group_key(self, group_id):
        """Return sorted-set key for one homogeneous work group."""
        return f"{self.keys['prefix']}:group:{group_id}"

    def groups(self):
        """Return deterministic group IDs and scan metadata."""
        return [
            (group_id, json.loads(metadata))
            for group_id, metadata in sorted(
                self.raw.hgetall(self.keys["groups"]).items()
            )
        ]

    def peek(self, group_id, limit):
        """Read one deterministic candidate slice without consuming it."""
        return self.raw.zrange(self.group_key(group_id), 0, max(0, limit - 1))

    def acknowledge(self, group_id, members):
        """Consume candidates after their SQL job commit succeeded."""
        if members:
            self.raw.zrem(self.group_key(group_id), *members)
        if self.raw.zcard(self.group_key(group_id)) == 0:
            pipe = self.raw.pipeline(transaction=True)
            pipe.delete(self.group_key(group_id))
            pipe.hdel(self.keys["groups"], group_id)
            pipe.execute()

    def empty(self):
        """Return whether every prepared group was consumed."""
        return self.raw.hlen(self.keys["groups"]) == 0

    def counts(self):
        """Return lightweight collection progress for UI polling."""
        meta = self.metadata()
        return {
            "checked": int(meta.get("checked", 0)),
            "retained": int(meta.get("retained", 0)),
            "stage": meta.get("stage"),
        }
