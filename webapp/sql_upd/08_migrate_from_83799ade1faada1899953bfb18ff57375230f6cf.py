import importlib.util
from pathlib import Path

import redis
import requests


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.py"
BATCH_SIZE = 1000
MEILI_INDEX = "plum"
REINDEX_PATTERNS = [
    "fqdn_requested:*",
    "fqdn_requesteds:*",
]


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


def load_kvrocks_config():
    """
    Read Kvrocks connection settings from config.py, with local defaults.
    """
    config = load_config_module()
    host = getattr(config, "KVROCKS_HOST", "localhost") if config else "localhost"
    port = getattr(config, "KVROCKS_PORT", 6666) if config else 6666
    return host, int(port)


def load_meili_config():
    """
    Read Meilisearch connection settings from config.py, with local defaults.
    """
    config = load_config_module()
    uri = (
        getattr(config, "MEILI_DATABASE_URI", "http://localhost:7700")
        if config
        else "http://localhost:7700"
    )
    key = getattr(config, "MEILI_KEY", "") if config else ""
    return uri.rstrip("/"), key


def delete_keys_by_pattern(redis_client, pattern, batch_size=1000):
    """
    Delete keys matching one pattern without blocking on KEYS.
    """
    deleted = 0
    batch = []
    for key in redis_client.scan_iter(match=pattern, count=batch_size):
        batch.append(key)
        if len(batch) >= batch_size:
            deleted += redis_client.delete(*batch)
            batch = []
    if batch:
        deleted += redis_client.delete(*batch)
    return deleted


def normalize_requested_fqdns(document):
    """
    Extract hostname entries of type user from one document.
    """
    requested = []
    seen = set()
    hostnames = ((document or {}).get("body") or {}).get("hostnames") or []
    for entry in hostnames:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type") or "").lower() != "user":
            continue
        hostname = str(entry.get("name") or "").strip().lower()
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        requested.append(hostname)
    return requested


def iter_meili_documents(meili_uri, meili_key, batch_size=BATCH_SIZE):
    """
    Iterate Meilisearch documents in batches.
    """
    headers = {}
    if meili_key:
        headers["Authorization"] = f"Bearer {meili_key}"
        headers["X-Meili-API-Key"] = meili_key

    offset = 0
    total = None
    session = requests.Session()

    while True:
        response = session.get(
            f"{meili_uri}/indexes/{MEILI_INDEX}/documents",
            params={"limit": batch_size, "offset": offset},
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        results = payload if isinstance(payload, list) else payload.get("results", [])
        if total is None and isinstance(payload, dict):
            total = payload.get("total")

        if not results:
            break

        yield results

        offset += len(results)
        if total is not None and offset >= total:
            break


def rebuild_fqdn_requested_index(redis_client, meili_uri, meili_key):
    """
    Rebuild fqdn_requested indexes from Meilisearch documents.
    """
    deleted = 0
    for pattern in REINDEX_PATTERNS:
        deleted_for_pattern = delete_keys_by_pattern(redis_client, pattern, BATCH_SIZE)
        deleted += deleted_for_pattern
        if deleted_for_pattern:
            print(f"Deleted {deleted_for_pattern} keys matching {pattern}", flush=True)

    stats = {
        "deleted": deleted,
        "processed": 0,
        "uids_with_requested_fqdn": 0,
        "indexed_values": 0,
    }

    for batch in iter_meili_documents(meili_uri, meili_key, BATCH_SIZE):
        pipe = redis_client.pipeline(transaction=False)
        for document in batch:
            stats["processed"] += 1
            uid = document.get("id")
            if not uid:
                continue

            requested_fqdns = normalize_requested_fqdns(document)
            if not requested_fqdns:
                continue

            stats["uids_with_requested_fqdn"] += 1
            for hostname in requested_fqdns:
                pipe.sadd(f"fqdn_requested:{hostname}", uid)
                pipe.sadd(f"fqdn_requesteds:{uid}", hostname)
                stats["indexed_values"] += 1

        pipe.execute()

        print(
            "Processed "
            f"{stats['processed']} documents; "
            f"uids_with_requested_fqdn={stats['uids_with_requested_fqdn']}; "
            f"indexed_values={stats['indexed_values']}",
            flush=True,
        )

    return stats


host, port = load_kvrocks_config()
meili_uri, meili_key = load_meili_config()
kvrocks = redis.Redis(host=host, port=port, decode_responses=True, db=0)
kvrocks.ping()

result = rebuild_fqdn_requested_index(kvrocks, meili_uri, meili_key)
print(
    "Kvrocks fqdn_requested migration complete: "
    f"deleted={result['deleted']} "
    f"processed={result['processed']} "
    f"uids_with_requested_fqdn={result['uids_with_requested_fqdn']} "
    f"indexed_values={result['indexed_values']}",
    flush=True,
)
