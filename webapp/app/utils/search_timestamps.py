"""Bounded scalar reads for already-matched per-IP timestamp metadata."""

from itertools import islice


def _read_batch(indexer, batch):
    """Yield normalized bounds only for selected UIDs still belonging to IPs."""
    membership = indexer.r.pipeline(transaction=False)
    for ip, uid in batch:
        membership.sismember(f"ip:{ip}", uid)
    selected = [pair for pair, present in zip(batch, membership.execute()) if present]
    if not selected:
        return
    metadata = indexer.r.pipeline(transaction=False)
    for _ip, uid in selected:
        metadata.hmget(f"doc:{uid}", "first_seen", "last_seen")
    for (ip, uid), values in zip(selected, metadata.execute()):
        first_seen, last_seen = indexer.normalize_seen_range(*values)
        yield ip, uid, {"first_seen": first_seen, "last_seen": last_seen}


def search_timestamps(indexer, results_ip, batch_size=250):
    """Read only selected members through the caller's pinned generation.

    Membership remains authoritative when UID-to-IP mappings disagree. Each
    batch returns at most one boolean and two timestamp fields per candidate,
    never an entire IP history or document hash. Backend failures propagate.
    """
    batch_size = max(1, min(500, int(batch_size)))
    result = {ip: {} for ip in results_ip}
    pairs = (
        (ip, uid) for ip, uids in results_ip.items() for uid in dict.fromkeys(uids)
    )
    while batch := list(islice(pairs, batch_size)):
        for ip, uid, bounds in _read_batch(indexer, batch):
            result[ip][uid] = bounds
    for timestamps in result.values():
        first = (
            row["first_seen"]
            for row in timestamps.values()
            if row["first_seen"] is not None
        )
        last = (
            row["last_seen"]
            for row in timestamps.values()
            if row["last_seen"] is not None
        )
        min_seen, max_seen = min(first, default=None), max(last, default=None)
        timestamps.update(min_seen=min_seen, max_seen=max_seen)
    return result
