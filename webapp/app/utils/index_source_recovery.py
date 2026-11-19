"""Preserve detached timestamp hashes left behind by legacy index rebuilds."""

import ipaddress
import json

from app.utils.index_generations import CONTROL, GenerationClient, read_json
from app.utils.index_reconciliation import FIELDS, write_barrier
from app.utils.result_parser import is_external_ip

SOURCE_CONFLICT = (
    "Non-public source conflicts with indexed history or incremental "
    "work. Review source/index consistency before retrying."
)


def _has_references(client, uid, addresses):
    """Treat partial indexes, contribution records and coverage as live data."""
    pipe = client.pipeline(transaction=False)
    pipe.zscore("first_seen_index", uid)
    pipe.zscore("last_seen_index", uid)
    pipe.sismember("all_uids", uid)
    for name in ("uid", "contributions", "coverage"):
        pipe.exists(f"{name}:{uid}")
    for field in FIELDS:
        pipe.scard(f"{field}s:{uid}")
    for address in addresses:
        pipe.sismember(f"ip:{address}", uid)
    values = pipe.execute()
    return any(value is not None for value in values[:2]) or any(values[2:])


def _matching_archive(metadata, address):
    """Recognize only a detached date hash for the same non-public address."""
    if set(metadata) - {"ip", "first_seen", "last_seen"}:
        return False
    try:
        retained = ipaddress.ip_address(metadata.get("ip"))
        return not is_external_ip(str(retained)) and (
            not address or retained == ipaddress.ip_address(address)
        )
    except ValueError:
        return False


def orphan_exclusion_metadata(raw, job, uid, address=None):
    """Return intact detached metadata, or None when exclusion would lose data.

    Empty metadata is valid for a Meili-only source. A retained hash must contain
    only IP/date fields, match the excluded source address, and have no indexed
    references in either generation. Never merge conflicting staging metadata.
    """
    if not job.get("full"):
        return None
    clients = [GenerationClient(raw, job[key]) for key in ("parent", "id")]
    documents = [client.hgetall(f"doc:{uid}") for client in clients]
    metadata = documents[0] or documents[1]
    if any(document and document != metadata for document in documents):
        return None
    addresses = {address} if address else set()
    if metadata:
        if not _matching_archive(metadata, address):
            return None
        addresses.add(metadata["ip"])
    if any(_has_references(client, uid, addresses) for client in clients):
        return None
    return metadata


def requeue_orphan_exclusion(raw, job):
    """Queue one narrowly validated recovery without replacing frozen inputs.

    Only the earlier orphan-hash conflict is eligible. A durable marker prevents
    an endless restart if source validation subsequently finds another conflict.
    The scheduler launches the normal worker, which rechecks source and snapshot.
    """
    if job.get("phase") != "blocked" or job.get("message") != SOURCE_CONFLICT:
        return job
    with write_barrier():
        current = read_json(raw, "job", {})
        if (
            current.get("id") != job.get("id")
            or current.get("phase") != "blocked"
            or current.get("message") != SOURCE_CONFLICT
        ):
            return current
        marker = CONTROL + "g:" + current["id"] + ":orphan_recovery:v1"
        if raw.exists(marker):
            return current
        pending = current.get("pending_uids", [])
        pipe = raw.pipeline(transaction=False)
        for uid in pending:
            pipe.sismember(CONTROL + "processed:" + current["id"], uid)
        remaining = [uid for uid, done in zip(pending, pipe.execute()) if not done]
        if not remaining or not orphan_exclusion_metadata(raw, current, remaining[0]):
            return current
        resumed = dict(
            current,
            phase="paused",
            retry_at=None,
            message="Retained orphan timestamps; queued source exclusion recheck",
        )
        pipe = raw.pipeline(transaction=True)
        pipe.set(marker, "1")
        pipe.set(CONTROL + "job", json.dumps(resumed, sort_keys=True))
        pipe.execute()
        return resumed
