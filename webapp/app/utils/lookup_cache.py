"""Shared, expiring enrichment responses outside search index generations."""

from functools import lru_cache
import json
import time

from flask import current_app, has_app_context
import redis


class LookupBusy(LookupError):
    """Another process is still retrieving this response; callers may retry."""


@lru_cache(maxsize=16)
def _client(host, port, timeout):
    return redis.Redis(
        host=host,
        port=port,
        db=0,
        decode_responses=True,
        socket_timeout=timeout,
        socket_connect_timeout=timeout,
    )


def configuration(config=None):
    """Use explicit worker configuration or the current web application."""
    if config is not None:
        return config
    return current_app.config if has_app_context() else {}


def lifetime(config, key, default):
    """Resolve positive integer hours, including older installations."""
    try:
        hours = int(config.get(key, default))
        return max(1, hours) * 3600
    except (ValueError, TypeError):
        return default * 3600


def cache_client(config):
    """Reuse a bounded raw connection pool; never wrap keys in a generation."""
    if not config.get("KVROCKS_HOST"):
        return None
    return _client(
        config["KVROCKS_HOST"],
        int(config.get("KVROCKS_PORT", 6666)),
        min(6, max(1, float(config.get("KVROCKS_SOCKET_TIMEOUT_SECONDS", 10)))),
    )


class ResponseCache:  # pylint: disable=too-few-public-methods
    """Atomically cache successful JSON-compatible values and coalesce misses."""

    def __init__(self, client, clock=None):
        self.client = client
        self.clock = clock or time.time

    def _read(self, key, ttl, validator):
        raw = self.client.get(key)
        if not raw:
            return None
        try:
            record = json.loads(raw)
            fetched = record["fetched_at"]
            expires = record["expires_at"]
            # Treat timestamps and payload validity as separate contracts.
            if (
                not isinstance(fetched, (int, float))
                or isinstance(fetched, bool)
                or not isinstance(expires, (int, float))
                or isinstance(expires, bool)
            ):
                return None
            if not fetched <= self.clock() < expires or expires - fetched != ttl:
                return None
            if "value" not in record or not validator(record["value"]):
                return None
            return dict(record, cached=True)
        except (ValueError, TypeError, KeyError):
            return None

    def _load(self, loader, ttl):
        value = loader()
        fetched = self.clock()
        return {
            "value": value,
            "fetched_at": fetched,
            "expires_at": fetched + ttl,
            "cached": False,
        }

    # Independent policy options keep source adapters explicit.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def get(
        self, key, ttl, loader, lease_seconds, force=False, validator=lambda value: True
    ):
        """Expire from completion, never extend on reads; failures are not stored."""
        if self.client is None:
            return self._load(loader, ttl)
        # Include policy in the key so processes with different settings cannot
        # consume or repeatedly overwrite each other's entries during restart.
        key = f"plum:lookup:v1:{key}:ttl:{ttl}"
        lock = None
        acquired = False
        try:
            if not force:
                hit = self._read(key, ttl, validator)
                if hit is not None:
                    return hit
            lock = self.client.lock(
                key + ":lock", timeout=lease_seconds, blocking_timeout=lease_seconds
            )
            acquired = lock.acquire()
        except redis.RedisError:
            return self._load(loader, ttl)
        if not acquired:
            raise LookupBusy("Lookup already in progress; try again shortly")
        try:
            if not force:
                try:
                    hit = self._read(key, ttl, validator)
                    if hit is not None:
                        return hit
                except redis.RedisError:
                    pass
            record = self._load(loader, ttl)
            try:
                # Redis lock uses a random token and owner-checked Lua release.
                # A worker whose lease expired cannot publish a stale response.
                self.client.eval(
                    "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    "return redis.call('set', KEYS[2], ARGV[2], 'EX', ARGV[3]) end",
                    2,
                    key + ":lock",
                    key,
                    lock.local.token,
                    json.dumps(record, allow_nan=False),
                    ttl,
                )
            except redis.RedisError:
                pass
            return record
        finally:
            try:
                lock.release()
            except redis.RedisError:
                pass


# pylint: disable=too-many-arguments,too-many-positional-arguments
def cached_response(
    key,
    setting,
    default,
    loader,
    lease_seconds,
    config=None,
    force=False,
    validator=lambda value: True,
):
    """Application adapter with fixed namespaces and caller-specific lifetime."""
    config = configuration(config)
    return ResponseCache(cache_client(config)).get(
        key,
        lifetime(config, setting, default),
        loader,
        lease_seconds,
        force=force,
        validator=validator,
    )


def cache_metadata(record):
    """Expose freshness only, separate from response data."""
    return {key: record[key] for key in ("cached", "fetched_at", "expires_at")}
