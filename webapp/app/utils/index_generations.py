"""Versioned Kvrocks keyspaces, with lazy copy-on-write and pinned readers.

Control keys are deliberately outside the logical search keyspace. A generation
owns even deleted keys: an empty set must never reveal its parent's old values.
Writers must hold the installation's write barrier while calling this module.
"""

import fnmatch
import json
import re
from uuid import uuid4
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
import fcntl

CONTROL = "plum:reconciliation:"
ACTIVE = CONTROL + "active"
READER_SCOPE = ContextVar("plum_index_reader_scope", default=None)


def generation_identity(client):
    """Identity for generation-sensitive caches, including legacy adapters."""
    return client.chain()[0] if isinstance(client, GenerationClient) else ""


def reader_generation(config):
    """Capture the current request's generation for an owner-bound cursor."""
    scope = READER_SCOPE.get() or {}
    client = scope.get((config["KVROCKS_HOST"], config["KVROCKS_PORT"]))
    return client.chain()[0] if client is not None else None


def lease_reader_generation(config, seconds, lease_id=None):
    """Keep a generation alive while an opaque continuation token can be used."""
    scope = READER_SCOPE.get() or {}
    client = scope.get((config["KVROCKS_HOST"], config["KVROCKS_PORT"]))
    if client is None or not client.chain()[0]:
        return None
    lease_id = lease_id or uuid4().hex
    if not re.fullmatch(r"[a-f0-9]{32}", lease_id):
        raise ValueError("Invalid reader lease")
    client.raw.set(f"{CONTROL}g:{client.generation}:lease:{lease_id}", "1", ex=seconds)
    return lease_id


def restore_reader_generation(config, generation):
    """Restore only a generation from trusted session/signed-cursor state."""
    if generation is None:
        return
    if not isinstance(generation, str) or not re.fullmatch(
        r"[a-f0-9]{32}|", generation
    ):
        raise ValueError("Invalid index generation")
    import redis  # pylint: disable=import-outside-toplevel

    endpoint = (config["KVROCKS_HOST"], config["KVROCKS_PORT"])
    scope = READER_SCOPE.get()
    if scope is None:
        scope = {}
        READER_SCOPE.set(scope)
    raw = redis.Redis(
        host=endpoint[0],
        port=endpoint[1],
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5,
    )
    scope[endpoint] = GenerationClient(raw, generation)


def pinned_read(function):
    """Pin all clients created during one export/report operation together."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        token = READER_SCOPE.set({})
        try:
            return function(*args, **kwargs)
        finally:
            READER_SCOPE.reset(token)

    return wrapped


@contextmanager
def file_lock(path, blocking=True, shared=False):
    """Serialize local processes without a stale-PID takeover race."""
    location = Path(path)
    location.parent.mkdir(parents=True, exist_ok=True)
    with location.open("a", encoding="utf-8") as handle:
        flags = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | (
            0 if blocking else fcntl.LOCK_NB
        )
        fcntl.flock(handle.fileno(), flags)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def generation_prefix(generation):
    """Legacy generation uses the existing, unprefixed keys."""
    return f"{CONTROL}g:{generation}:data:" if generation else ""


class GenerationClient:
    """Redis subset used by Plum, resolving one pinned generation per reader."""

    READS = {
        "get",
        "hget",
        "hgetall",
        "hmget",
        "smembers",
        "scard",
        "sismember",
        "sscan",
        "zrangebyscore",
        "zrange",
        "zcard",
        "zscore",
        "exists",
        "type",
    }
    WRITES = {"set", "hset", "hdel", "sadd", "srem", "zadd", "zrem", "delete"}

    def __init__(self, client, generation=None, writable=False):
        self.raw = client
        self.generation = generation
        self.writable = writable
        self._chain = None

    def chain(self):
        """Resolve once; retained ancestors keep long-running readers valid."""
        if self._chain is None:
            if self.generation is None:
                value = self.raw.get(ACTIVE)
                self.generation = value if isinstance(value, str) else ""
            chain = []
            current = self.generation
            while current:
                if current in chain:
                    raise RuntimeError("Cyclic index generation")
                chain.append(current)
                parent = self.raw.get(f"{CONTROL}g:{current}:parent")
                if parent is None:
                    raise RuntimeError("Missing index generation metadata")
                if parent == "-":
                    self._chain = chain
                    return chain
                current = parent
            self._chain = chain + [""]
        return self._chain

    @staticmethod
    def owned(generation):
        """Key containing the ownership/tombstone set."""
        return f"{CONTROL}g:{generation}:owned"

    def resolve_many(self, keys):
        """Batch ownership lookups rather than issuing one RTT per key."""
        unresolved = set(keys)
        resolved = {}
        for generation in self.chain():
            if not unresolved:
                break
            pending = sorted(unresolved)
            if not generation:
                resolved.update({key: key for key in pending})
                unresolved.clear()
                break
            pipe = self.raw.pipeline(transaction=False)
            for key in pending:
                pipe.sismember(self.owned(generation), key)
            for key, present in zip(pending, pipe.execute()):
                if present:
                    resolved[key] = generation_prefix(generation) + key
                    unresolved.remove(key)
        # A full generation has no legacy fallback. Missing keys resolve empty.
        for key in unresolved:
            resolved[key] = generation_prefix(self.generation) + key
        return resolved

    def prepare_writes(self, keys):
        """Copy affected keys before ownership; caller holds the write barrier."""
        self.chain()
        if not self.writable and (self.generation or self.raw.get(CONTROL + "desired")):
            raise RuntimeError("Managed index: use the ingestion/reconciliation worker")
        if not self.generation:
            return {key: key for key in keys}
        resolved = self.resolve_many(keys)
        targets = {key: generation_prefix(self.generation) + key for key in keys}
        inherited = [
            (source, targets[key])
            for key, source in resolved.items()
            if source != targets[key]
        ]
        # A batch of large COPY commands can exceed the socket timeout. Record
        # each successful copy on the server, even if its response is lost, so
        # the next export resumes instead of deleting and copying it again.
        copy_and_own = """
            redis.call('DEL', KEYS[2])
            if redis.call('EXISTS', KEYS[1]) == 1 then
                redis.call('COPY', KEYS[1], KEYS[2], 'REPLACE')
            end
            redis.call('SADD', KEYS[3], ARGV[1])
            return 1
        """
        logical_keys = {target: key for key, target in targets.items()}
        for source, target in inherited:
            self.raw.eval(
                copy_and_own,
                3,
                source,
                target,
                self.owned(self.generation),
                logical_keys[target],
            )
        if keys:
            self.raw.sadd(self.owned(self.generation), *sorted(keys))
        return targets

    def run(self, commands):
        """Map logical keys for a batch, preserving command result ordering."""
        keys = set()
        writes = set()
        for name, args, _kwargs in commands:
            if name not in self.READS | self.WRITES:
                raise ValueError(f"Unsupported generation command: {name}")
            selected = args if name == "delete" else args[:1]
            keys.update(selected)
            if name in self.WRITES:
                writes.update(selected)
        resolved = self.resolve_many(keys)
        if writes:
            resolved.update(self.prepare_writes(writes))
        pipe = self.raw.pipeline(transaction=bool(writes))
        for name, args, kwargs in commands:
            mapped = (
                tuple(resolved[key] for key in args)
                if name == "delete"
                else (resolved[args[0]], *args[1:])
            )
            getattr(pipe, name)(*mapped, **kwargs)
        return pipe.execute()

    def __getattr__(self, name):
        if name in self.READS | self.WRITES:
            return lambda *args, **kwargs: self.run([(name, args, kwargs)])[0]
        raise AttributeError(name)

    def execute_command(self, name, *args, **kwargs):
        """Expose redis-py's command hook to request diagnostics."""
        return self.run([(str(name).lower(), args, kwargs)])[0]

    def flushdb(self):
        """Preserve isolated legacy maintenance; never erase managed state."""
        if self.raw.get(ACTIVE) or self.raw.get(CONTROL + "desired"):
            raise RuntimeError("Managed index: queue a full background rebuild")
        return self.raw.flushdb()

    def pipeline(self, transaction=True):
        """Create a logical pipeline; writes are always transactional."""
        return GenerationPipeline(self, transaction)

    def scan_iter(self, match="*", count=100):
        """Enumerate visible keys without exposing control keys or ancestors."""
        for generation in self.chain():
            prefix = generation_prefix(generation)
            for physical in self.raw.scan_iter(match=prefix + match, count=count):
                if not generation and physical.startswith(CONTROL):
                    continue
                logical = physical[len(prefix) :]
                if self.resolve_many([logical])[logical] == physical:
                    yield logical

    def sscan_iter(self, name, match=None, count=100):
        """Stream set members without materializing the full UID catalogue."""
        cursor = 0
        while True:
            cursor, values = self.sscan(name, cursor=cursor, count=count)
            for value in values:
                if match is None or fnmatch.fnmatchcase(value, match):
                    yield value
            if not cursor:
                break


class GenerationPipeline:
    """Small redis-py compatible pipeline for the search/index command subset."""

    def __init__(self, client, transaction):
        self.client = client
        self.transaction = transaction
        self.commands = []

    @property
    def command_stack(self):
        """Keep existing search diagnostics compatible."""
        return [((name.upper(), *args), kwargs) for name, args, kwargs in self.commands]

    def __getattr__(self, name):
        if name not in self.client.READS | self.client.WRITES:
            raise AttributeError(name)

        def queue(*args, **kwargs):
            self.commands.append((name, args, kwargs))
            return self

        return queue

    def execute(self):
        """Execute once and clear queued commands even after a failed batch."""
        commands, self.commands = self.commands, []
        return self.client.run(commands)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.commands.clear()


def read_json(client, key, default=None):
    """Read durable control state; malformed state must not reset progress."""
    value = client.get(CONTROL + key)
    return json.loads(value) if value is not None else default


def write_json(client, key, value):
    """Publish a complete control record with a single atomic SET."""
    client.set(CONTROL + key, json.dumps(value, sort_keys=True))
