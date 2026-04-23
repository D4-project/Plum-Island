import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import redis


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.py"
BATCH_SIZE = 1000


def load_config_module():
    """
    Load the deployed config.py when available.
    """
    try:
        spec = importlib.util.spec_from_file_location("plum_config", CONFIG_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def normalize_timestamp(value):
    """
    Convert known timestamp formats to epoch seconds.
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        timestamp = float(value)
    else:
        value = str(value).strip()
        if not value:
            return None

        try:
            timestamp = float(value)
        except ValueError:
            try:
                if value.endswith("Z"):
                    value = f"{value[:-1]}+00:00"
                date_value = datetime.fromisoformat(value)
                if date_value.tzinfo is None:
                    date_value = date_value.replace(tzinfo=timezone.utc)
                timestamp = date_value.timestamp()
            except ValueError:
                return None

    if timestamp > 1_000_000_000_000:
        timestamp = timestamp / 1000
    if timestamp < 0:
        return None
    return int(timestamp)


def normalize_seen_range(first_seen, last_seen):
    """
    Normalize first_seen/last_seen as an ordered epoch-second interval.
    """
    first_seen = normalize_timestamp(first_seen)
    last_seen = normalize_timestamp(last_seen)

    if first_seen is None and last_seen is None:
        return None, None
    if first_seen is None:
        first_seen = last_seen
    if last_seen is None:
        last_seen = first_seen
    if first_seen > last_seen:
        first_seen, last_seen = last_seen, first_seen
    return first_seen, last_seen


def load_kvrocks_config():
    """
    Read Kvrocks connection settings from config.py, with local defaults.
    """
    config = load_config_module()
    host = getattr(config, "KVROCKS_HOST", "localhost") if config else "localhost"
    port = getattr(config, "KVROCKS_PORT", 6666) if config else 6666
    return host, int(port)


def rebuild_time_indexes(kvrocks):
    """
    Rebuild first_seen_index and last_seen_index from doc:{uid} hashes.
    """
    stats = {
        "seen": 0,
        "indexed": 0,
        "skipped": 0,
        "fixed_ranges": 0,
        "millisecond_values": 0,
    }

    kvrocks.delete("first_seen_index", "last_seen_index")

    pipe = kvrocks.pipeline(transaction=False)
    queued_docs = 0
    for key in kvrocks.scan_iter(match="doc:*", count=BATCH_SIZE):
        stats["seen"] += 1
        uid = key.split("doc:", 1)[1]
        data = kvrocks.hgetall(key)
        raw_first_seen = normalize_timestamp(data.get("first_seen"))
        raw_last_seen = normalize_timestamp(data.get("last_seen"))
        first_seen, last_seen = normalize_seen_range(
            data.get("first_seen"), data.get("last_seen")
        )

        if first_seen is None or last_seen is None:
            stats["skipped"] += 1
            continue

        if (
            raw_first_seen is not None
            and raw_last_seen is not None
            and raw_first_seen > raw_last_seen
        ):
            stats["fixed_ranges"] += 1
        if any(
            str(value or "").strip().isdigit()
            and float(str(value).strip()) > 1_000_000_000_000
            for value in (data.get("first_seen"), data.get("last_seen"))
        ):
            stats["millisecond_values"] += 1

        pipe.hset(
            key,
            mapping={
                "first_seen": str(first_seen),
                "last_seen": str(last_seen),
            },
        )
        pipe.zadd("first_seen_index", {uid: first_seen})
        pipe.zadd("last_seen_index", {uid: last_seen})
        stats["indexed"] += 1
        queued_docs += 1

        if queued_docs >= BATCH_SIZE:
            pipe.execute()
            pipe = kvrocks.pipeline(transaction=False)
            queued_docs = 0

    if queued_docs:
        pipe.execute()

    return stats


host, port = load_kvrocks_config()
kvrocks = redis.Redis(host=host, port=port, decode_responses=True, db=0)
kvrocks.ping()

result = rebuild_time_indexes(kvrocks)
print(
    "Kvrocks timestamp migration complete: "
    f"seen={result['seen']} "
    f"indexed={result['indexed']} "
    f"skipped={result['skipped']} "
    f"fixed_ranges={result['fixed_ranges']} "
    f"millisecond_values={result['millisecond_values']}"
)
