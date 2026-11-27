"""Bounded existence checks over indexed historical observations."""

from itertools import islice
import ipaddress
import time

from app.utils.search_plan import build_plan

BATCH_SIZE = 64


def _seed_keys(node):
    """Choose exact index sets that cover every possible match, when available."""
    if node.kind == "term":
        field, (value,) = node.fields[0]
        if "." in field or field == "net" or (field == "engine" and value == "nmap"):
            return ()
        return (f"{field}:{value}",)
    if node.kind == "not":
        return ()
    seeds = [_seed_keys(child) for child in node.children]
    if node.kind == "all":
        return min((keys for keys in seeds if keys), key=len, default=())
    if all(seeds):
        return tuple(dict.fromkeys(key for keys in seeds for key in keys))
    return ()


def _candidate_batches(client, keys, start, end, check_deadline):
    if keys:
        for key in keys:
            cursor = 0
            while True:
                check_deadline()
                cursor, uids = client.sscan(key, cursor=cursor, count=BATCH_SIZE)
                # COUNT is advisory. Keep the subsequent reads bounded.
                entries = iter(uids)
                while batch := list(islice(entries, BATCH_SIZE)):
                    yield batch
                if not cursor:
                    break
        return

    offset = 0
    while True:
        check_deadline()
        entries = client.zrangebyscore(
            "last_seen_index", start, end, start=offset, num=BATCH_SIZE, withscores=True
        )
        if not entries:
            return
        yield [uid for uid, _ in entries]
        score = entries[-1][1]
        if score != start:
            start, offset = score, 0
        offset += sum(seen == score for _, seen in entries)


def plan_terms(node):
    """Yield the indexed predicates used by this plan."""
    if node.kind == "term":
        yield node
    for child in node.children:
        yield from plan_terms(child)


def _matches(node, matches):
    if node.kind == "term":
        return matches[node]
    if node.kind == "not":
        return not _matches(node.children[0], matches)
    combine = all if node.kind == "all" else any
    return combine(_matches(child, matches) for child in node.children)


def _evaluate_term(indexer, pipe, term, uid, ip):
    """Queue the index read and return how to interpret its response."""
    field, (value,) = term.fields[0]
    base, _, modifier = field.partition(".")
    if base == "net":
        network = ipaddress.ip_network(value, strict=False)
        return False, lambda _response: ip in network
    if field == "engine" and value not in {"nmap", "masscan"}:
        return False, lambda _response: False
    if not modifier:
        key = "engine:masscan" if field == "engine" else f"{field}:{value}"
        pipe.sismember(key, uid)
        return True, (
            (lambda present: not present)
            if field == "engine" and value == "nmap"
            else bool
        )
    if modifier in {"not", "nt"}:
        # Search Scans' time-scoped matcher has no matches for these modifiers.
        return False, lambda _response: False

    pipe.smembers(f"{base}s:{uid}")

    def match_value(values):
        # pylint: disable=protected-access
        if base == "http_headval":
            header, _, expected = value.partition(":")
            prefix = header.strip() + ":"
            return any(
                indexed.startswith(prefix)
                and indexer._modifier_matches(
                    indexed[len(prefix) :], expected.strip(), modifier
                )
                for indexed in values
            )
        return any(
            indexer._modifier_matches(indexed, value, modifier) for indexed in values
        )

    return True, match_value


def _recent_candidates(client, uids, start, end):
    """Read observation metadata in one pipeline and discard stale entries."""
    pipe = client.pipeline(transaction=False)
    for uid in uids:
        pipe.get(f"uid:{uid}")
        pipe.zscore("last_seen_index", uid)
    metadata = pipe.execute()
    for uid, ip, seen in zip(uids, metadata[::2], metadata[1::2]):
        if ip and seen is not None and start <= seen <= end:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            yield uid, address


def evaluate_observation_batch(indexer, terms, candidates):
    """Evaluate each predicate once per observation in one bounded pipeline."""
    pipe = indexer.r.pipeline(transaction=False)
    checks = [
        [_evaluate_term(indexer, pipe, term, uid, ip) for term in terms]
        for uid, ip in candidates
    ]
    responses = iter(pipe.execute())
    for (uid, ip), per_observation in zip(candidates, checks):
        matches = {
            term: check(next(responses, None) if reads_index else None)
            for term, (reads_index, check) in zip(terms, per_observation)
        }
        yield uid, ip, matches


def observation_batches(  # pylint: disable=too-many-arguments
    indexer, query, start, end, timeout=10, *, progress=None
):
    """Yield matched observations with predicate evidence for each index page."""
    deadline = time.monotonic() + timeout if timeout is not None else None

    def check_deadline():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Search filter verification timed out.")

    client = indexer.r
    plan = build_plan(query, scoped_membership=True, factor=False)
    terms = tuple(dict.fromkeys(plan_terms(plan)))
    for uids in _candidate_batches(
        client, _seed_keys(plan), start, end, check_deadline
    ):
        check_deadline()
        candidates = list(_recent_candidates(client, uids, start, end))
        if progress is not None:
            progress(len(uids))
        if candidates:
            matches = [
                item
                for item in evaluate_observation_batch(indexer, terms, candidates)
                if _matches(plan, item[2])
            ]
            if matches:
                yield plan, matches
        check_deadline()


def chronological_observation_batches(
    indexer,
    query,
    start,
    end,
    timeout=None,
    *,
    resume=None,
):  # pylint: disable=too-many-arguments,too-many-locals
    """Read only the frozen time window, newest first, with a safe page cursor."""
    deadline = time.monotonic() + timeout if timeout is not None else None

    def check_deadline():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Search filter verification timed out.")

    client = indexer.r
    plan = build_plan(query, scoped_membership=True, factor=False)
    terms = tuple(dict.fromkeys(plan_terms(plan)))
    maximum, offset = resume or (end, 0)
    while maximum >= start:
        check_deadline()
        entries = client.zrevrangebyscore(
            "last_seen_index",
            maximum,
            start,
            start=offset,
            num=BATCH_SIZE,
            withscores=True,
        )
        if not entries:
            return
        last_score = entries[-1][1]
        next_offset = offset if last_score == maximum else 0
        next_offset += sum(score == last_score for _, score in entries)
        cursor = (last_score, next_offset)
        candidates = list(
            _recent_candidates(client, [uid for uid, _score in entries], start, end)
        )
        matches = []
        if candidates:
            matches = [
                item
                for item in evaluate_observation_batch(indexer, terms, candidates)
                if _matches(plan, item[2])
            ]
        yield plan, matches, cursor, len(entries)
        maximum, offset = cursor


def matching_observations(indexer, query, start, end, timeout=10):
    """Stream matching UIDs without materializing the result set."""
    for _plan, matches in observation_batches(indexer, query, start, end, timeout):
        for uid, _ip, _predicates in matches:
            yield uid


def has_observation(indexer, query, start, end, timeout=10):
    """Stop on the first match without counting or sorting search results."""
    return (
        next(matching_observations(indexer, query, start, end, timeout), None)
        is not None
    )
