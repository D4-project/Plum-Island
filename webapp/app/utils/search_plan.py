"""Request-local read-only candidate planning using existing index cardinalities."""

from collections import Counter
import ipaddress
import time

try:
    from .search_query import Expression, combine, query_expression
except ImportError:
    from search_query import Expression, combine, query_expression


def _junction(kind, children):
    """Flatten associative operations and eliminate repeated operands."""
    result = []
    seen = set()
    for child in children:
        candidates = child.children if child.kind == kind else (child,)
        for candidate in candidates:
            if candidate not in seen:
                result.append(candidate)
                seen.add(candidate)
    return combine(kind, result)


def _group_plan(fields):
    """Preserve IP/net union and the order-sensitive legacy header fallback."""
    positive = tuple(
        (field, values) for field, values in fields if not field.startswith("!")
    )
    negative = [
        Expression("not", (Expression("term", fields=((field[1:], (value,)),)),))
        for field, values in fields
        if field.startswith("!")
        for value in values
    ]
    if any(field.split(".")[0] == "http_headval" for field, _ in positive):
        positives = [Expression("legacy", fields=positive)] if positive else []
    else:
        networks = []
        positives = []
        for field, values in positive:
            target = networks if field in {"ip", "net"} else positives
            target.extend(
                Expression("term", fields=((field, (value,)),)) for value in values
            )
        if networks:
            positives.append(_junction("any", networks))
    return _junction("all", positives + negative)


def build_plan(query):
    """Factor common conjunctions without ever expanding into a Cartesian product."""
    node = query_expression(query)
    if node.kind == "criteria":
        fields = tuple(
            (field.lower(), tuple(str(v).lower() for v in values))
            for field, values in node.fields
        )
        return _group_plan(fields)
    node = _junction(node.kind, [build_plan(child) for child in node.children])
    if node.kind != "any" or len(node.children) < 2:
        return node
    branches = [
        child.children if child.kind == "all" else (child,) for child in node.children
    ]
    common_set = set(branches[0]).intersection(
        *(set(branch) for branch in branches[1:])
    )
    common = [child for child in branches[0] if child in common_set]
    if not common:
        return node
    if any(all(child in common_set for child in branch) for branch in branches):
        return _junction("all", common)
    remaining = [
        _junction("all", [child for child in branch if child not in common_set])
        for branch in branches
    ]
    return _junction("all", common + [_junction("any", remaining)])


def _leaves(node):
    if node.kind in {"term", "legacy"}:
        yield node
    else:
        for child in node.children:
            yield from _leaves(child)


def _counter_key(node):
    """Known exact cardinality, or a parent-network upper bound; never scan to count."""
    if node.kind != "term":
        return None
    field, (value,) = node.fields[0]
    if "." in field:
        return None
    if field == "net":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if network.prefixlen < 16:
            return None
        if network.prefixlen > 24:
            network = network.supernet(new_prefix=24)
        value = network.with_prefixlen
    return f"{field}:{value}"


def _bounded(node):
    if node.kind == "not":
        return False
    if node.kind in {"term", "legacy"}:
        return True
    bounds = [_bounded(child) for child in node.children]
    return any(bounds) if node.kind == "all" else bool(bounds) and all(bounds)


class CandidatePlanner:  # pylint: disable=too-many-instance-attributes
    """One execution scope, no persistent statistics or cross-request result cache."""

    def __init__(self, indexer, query, scope=None, diagnostics=None):
        self.indexer = indexer
        self.scope = None if scope is None else set(scope)
        self.diagnostics = diagnostics
        started = time.perf_counter()
        self.plan = build_plan(query)
        self.uses = Counter(_leaves(self.plan))
        self.labels = {
            node: f"p{position}" for position, node in enumerate(self.uses, 1)
        }
        self.counts = {}
        self.cache = {}
        self.estimates = {}
        self.events = []
        self._read_counts()
        self.estimate(self.plan)
        self.planning_ms = (time.perf_counter() - started) * 1000

    def _read_counts(self):
        if self.scope == set():
            return
        keys = list(
            dict.fromkeys(key for node in self.uses if (key := _counter_key(node)))
        )
        if len(keys) == 1:
            self.counts[keys[0]] = self.indexer.r.scard(keys[0])
        elif keys:
            pipe = self.indexer.r.pipeline(transaction=False)
            for key in keys:
                pipe.scard(key)
            self.counts.update(zip(keys, pipe.execute()))

    def estimate(self, node):
        """Estimate upper bounds only; they select order, never prove a match."""
        if node in self.estimates:
            return self.estimates[node]
        if node.kind in {"term", "legacy"}:
            value = self.counts.get(_counter_key(node))
        elif node.kind == "not":
            value = None
        else:
            values = [self.estimate(child) for child in node.children]
            known = [value for value in values if value is not None]
            if node.kind == "all":
                value = min(known) if known else None
            else:
                value = sum(known) if len(known) == len(values) else None
        self.estimates[node] = value
        return value

    def _order(self, node, scope):
        def rank(child):
            estimate = self.estimate(child)
            scoped = (
                min(estimate, len(scope))
                if estimate is not None and scope is not None
                else estimate
            )
            return (
                not _bounded(child),
                estimate is None,
                scoped if scoped is not None else float("inf"),
                estimate if estimate is not None else float("inf"),
            )

        return sorted(node.children, key=rank)

    def _leaf(self, node, scope):
        cached = node in self.cache
        if cached:
            result = self.cache[node]
        elif node.kind == "legacy":
            # Original root scope is deliberate: the unscoped header fallback
            # is not equivalent to calling the scoped matcher after reordering.
            if self.scope is None:
                result = set(self.indexer.get_uids_by_criteria(node.criteria()))
            else:
                result = set(
                    self.indexer.get_uids_by_criteria_scoped(
                        node.criteria(), self.scope
                    )
                )
        else:
            field, (value,) = node.fields[0]
            if field == "net":
                # Reused predicates need a root-scope cache; other CIDRs can
                # filter IP mappings inside the already narrowed candidates.
                network_scope = self.scope if self.uses[node] > 1 else scope
                # Preserve indexed-mask resolution and final IP checks.
                # pylint: disable-next=protected-access
                result = self.indexer._get_uids_for_net_value(value, network_scope)
            elif "." not in field and field != "http_headval":
                result = set(self.indexer.r.smembers(f"{field}:{value}"))
            elif scope is None:
                result = set(self.indexer.get_uids_by_criteria(node.criteria()))
            else:
                result = set(
                    self.indexer.get_uids_by_criteria_scoped(node.criteria(), scope)
                )
            # Cache only repeated direct predicates, scoped to this execution's
            # root, never a narrower branch whose omissions would poison reuse.
            if self.uses[node] > 1 and _counter_key(node) is not None:
                if self.scope is not None:
                    result = result.intersection(self.scope)
                self.cache[node] = result
        result = result.intersection(scope) if scope is not None else set(result)
        if self.diagnostics is not None:
            self.events.append(
                {
                    "predicate": self.labels[node],
                    "estimate": self.estimate(node),
                    "input_uids": None if scope is None else len(scope),
                    "matched_uids": len(result),
                    "cached": cached,
                    "legacy": node.kind == "legacy",
                }
            )
        return result

    def _evaluate(self, node, scope):
        if scope is not None and not scope:
            return set()
        if node.kind in {"term", "legacy"}:
            return self._leaf(node, scope)
        if node.kind == "not":
            if scope is None:
                raise ValueError("An exclusion requires positive candidates")
            return scope.difference(self._evaluate(node.children[0], scope))
        if node.kind == "any":
            result = set()
            for child in node.children:
                result.update(self._evaluate(child, scope))
            return result
        result = scope
        for child in self._order(node, scope):
            result = self._evaluate(child, result)
            if not result:
                break
        return set(result or [])

    def execute(self):
        """Return matching UIDs and opt-in anonymous plan diagnostics."""
        result = self._evaluate(self.plan, self.scope)
        if self.diagnostics is not None:
            self.diagnostics.planner = {
                "planning_ms": self.planning_ms,
                "root_estimate": self.estimate(self.plan),
                "counter_keys": len(self.counts),
                "predicates": [
                    {
                        "id": label,
                        "fields": [field for field, _ in node.fields],
                        "estimate": self.estimate(node),
                    }
                    for node, label in self.labels.items()
                ],
                "steps": self.events,
            }
        return result
