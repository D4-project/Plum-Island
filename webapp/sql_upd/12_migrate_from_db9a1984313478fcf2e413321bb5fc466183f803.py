import importlib.util
from pathlib import Path

import redis
import requests
from pyfaup import Url  # pylint: disable=no-name-in-module


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.py"
BATCH_SIZE = 1000
MEILI_INDEX = "plum"
REINDEX_PATTERNS = [
    "domain_requested:*",
    "domain_requesteds:*",
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


def load_domain_config():
    """
    Read domain validation settings from config.py.
    """
    config = load_config_module()
    if not config:
        return False, [], []
    return (
        bool(getattr(config, "ONLINETLD", False)),
        [str(tld).lower() for tld in getattr(config, "TLDS", [])],
        [str(tld).lower() for tld in getattr(config, "TLDADD", [])],
    )


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


def parse_requested_domain(hostname, online_tld, tlds, tldadd):
    """
    Extract the validated registrable domain from one requested hostname.
    """
    hostname = str(hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return None

    try:
        url = Url(f"http://{hostname}")
    except (ValueError, TypeError):
        return None

    suffix = url.suffix
    if not suffix:
        return None

    suffix_value = str(suffix).lower()
    parse = False
    if online_tld:
        if suffix_value in tlds:
            parse = True
    else:
        if suffix.is_known():
            parse = True
    if suffix_value in tldadd:
        parse = True

    if not parse or not url.domain:
        return None
    return str(url.domain).lower()


def normalize_requested_domains(document, online_tld, tlds, tldadd):
    """
    Extract domain_requested values from hostname entries of type user.
    """
    requested = []
    seen = set()
    hostnames = ((document or {}).get("body") or {}).get("hostnames") or []
    for entry in hostnames:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type") or "").lower() != "user":
            continue
        domain = parse_requested_domain(entry.get("name"), online_tld, tlds, tldadd)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        requested.append(domain)
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


def rebuild_domain_requested_index(redis_client, meili_uri, meili_key):
    """
    Rebuild domain_requested indexes from Meilisearch documents.
    """
    online_tld, tlds, tldadd = load_domain_config()
    deleted = 0
    for pattern in REINDEX_PATTERNS:
        deleted_for_pattern = delete_keys_by_pattern(redis_client, pattern, BATCH_SIZE)
        deleted += deleted_for_pattern
        if deleted_for_pattern:
            print(f"Deleted {deleted_for_pattern} keys matching {pattern}", flush=True)

    stats = {
        "deleted": deleted,
        "processed": 0,
        "uids_with_requested_domain": 0,
        "indexed_values": 0,
    }

    for batch in iter_meili_documents(meili_uri, meili_key, BATCH_SIZE):
        pipe = redis_client.pipeline(transaction=False)
        for document in batch:
            stats["processed"] += 1
            uid = document.get("id")
            if not uid:
                continue

            requested_domains = normalize_requested_domains(
                document,
                online_tld,
                tlds,
                tldadd,
            )
            if not requested_domains:
                continue

            stats["uids_with_requested_domain"] += 1
            for domain in requested_domains:
                pipe.sadd(f"domain_requested:{domain}", uid)
                pipe.sadd(f"domain_requesteds:{uid}", domain)
                stats["indexed_values"] += 1

        pipe.execute()

        print(
            "Processed "
            f"{stats['processed']} documents; "
            f"uids_with_requested_domain={stats['uids_with_requested_domain']}; "
            f"indexed_values={stats['indexed_values']}",
            flush=True,
        )

    return stats


host, port = load_kvrocks_config()
meili_uri, meili_key = load_meili_config()
kvrocks = redis.Redis(host=host, port=port, decode_responses=True, db=0)
kvrocks.ping()

result = rebuild_domain_requested_index(kvrocks, meili_uri, meili_key)
print(
    "Kvrocks domain_requested migration complete: "
    f"deleted={result['deleted']} "
    f"processed={result['processed']} "
    f"uids_with_requested_domain={result['uids_with_requested_domain']} "
    f"indexed_values={result['indexed_values']}",
    flush=True,
)
