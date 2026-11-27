"""Prepare durable scan targets from historical search observations."""

import ipaddress
import logging
from datetime import timedelta
from itertools import islice

from meilisearch.errors import MeilisearchError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.models import (
    FilteredScanTargets,
    ScanProfileCycles,
    ScanProfiles,
    TagRules,
    Targets,
)
from app.utils.domains import is_hostname_syntax
from app.utils.index_generations import pinned_read
from app.utils.kvrocks import KVrocksIndexer
from app.utils.result_parser import parse_json
from app.utils.search_existence import matching_observations
from app.utils.search_query import iter_criteria, query_expression
from app.utils.tagrules import (
    compile_tag_rule_records,
    document_matches_criteria_groups,
)
from app.utils.timeutils import utcnow_naive

logger = logging.getLogger("flask_appbuilder")
PORT_EVIDENCE_FIELDS = {
    "tag",
    "banner",
    "service",
    "nodata",
    "http_title",
    "http_header",
    "http_headval",
    "http_server",
    "http_cookiename",
    "http_etag",
    "x509_issuer",
    "x509_subject",
    "x509_issuer_cn",
    "x509_subject_cn",
    "x509_san",
}
DIRECT_PORT_FIELDS = PORT_EVIDENCE_FIELDS - {"tag"}
REQUESTED_HOST_FIELDS = {"fqdn_requested", "domain_requested"}
PREPARATION_BATCH_SIZE = 100


def query_can_prove_port(criteria):
    """Return whether a positive query term identifies an observed port."""
    return any(
        field.lstrip("!").partition(".")[0] in PORT_EVIDENCE_FIELDS
        and field.lstrip("!").partition(".")[2] not in {"not", "nt"}
        for group in iter_criteria(criteria)
        for field in group
        if not field.startswith("!")
    )


def _tag_term_matches(document, field, values):
    negate = field.startswith("!")
    _base, _, modifier = field.removeprefix("!").partition(".")
    candidates = {
        str(tag).strip().lower() for tag in document.get("tag", []) if str(tag).strip()
    }
    for raw_value in values:
        value = str(raw_value).strip().lower()
        if modifier in {"like", "lk"}:
            matched = any(value in candidate for candidate in candidates)
        elif modifier in {"begin", "bg"}:
            matched = any(candidate.startswith(value) for candidate in candidates)
        elif modifier in {"not", "nt"}:
            matched = value not in candidates
        else:
            matched = value in candidates
        if matched == negate:
            return False
    return True


def _port_query_matches(document, criteria):
    """Match query syntax while allowing already proven per-port tags."""
    node = query_expression(criteria)
    if node.kind == "criteria":
        for field, values in node.fields:
            if field.removeprefix("!").partition(".")[0] == "tag":
                if not _tag_term_matches(document, field, values):
                    return False
            elif not document_matches_criteria_groups(
                document, [{field: list(values)}]
            ):
                return False
        return True
    matches = (_port_query_matches(document, child) for child in node.children)
    return all(matches) if node.kind == "all" else any(matches)


def _match_with_port_evidence(
    document, criteria, proven_tags, direct_fields=DIRECT_PORT_FIELDS
):
    """Return query truth plus proof that one matching branch belongs to this port."""
    node = query_expression(criteria)
    if node.kind == "criteria":
        if not _port_query_matches(document, node):
            return False, False
        evidence = False
        for field, values in node.fields:
            if field.startswith("!"):
                continue
            base, _, modifier = field.partition(".")
            if modifier in {"not", "nt"}:
                continue
            if base in direct_fields:
                evidence = True
            elif base == "tag" and proven_tags:
                evidence = True
        return True, evidence

    children = [
        _match_with_port_evidence(document, child, proven_tags, direct_fields)
        for child in node.children
    ]
    if node.kind == "all":
        return all(match for match, _ in children), any(
            match and evidence for match, evidence in children
        )
    return any(match for match, _ in children), any(
        match and evidence for match, evidence in children
    )


def _port_tags(parsed, rules):
    """Keep only tags transitively justified by evidence on this scoped port."""
    proven = {
        str(tag).lower()
        for tag in parsed.get("tag", [])
        if str(tag).lower() == "proto:tls"
    }
    while True:
        before = len(proven)
        document = dict(parsed, tag=sorted(proven))
        for rule in rules:
            matched, has_evidence = _match_with_port_evidence(
                document, rule.get("criteria_groups", []), proven
            )
            if matched and has_evidence:
                proven.update(str(tag).lower() for tag in rule.get("tags", []))
        if len(proven) == before:
            return sorted(proven)


def _configured_targets(document, exact_targets, networks):
    """Return every configured scan identity represented by one observation."""
    configured = []
    body = document.get("body") or {}
    for hostname in body.get("hostnames") or []:
        if hostname.get("type") != "user":
            continue
        name = str(hostname.get("name") or "").strip().rstrip(".").lower()
        if is_hostname_syntax(name) and name in exact_targets:
            candidate = (exact_targets[name], "fqdn", name)
            if candidate not in configured:
                configured.append(candidate)
    try:
        address = ipaddress.ip_address(document.get("ip"))
    except (TypeError, ValueError):
        return configured
    address_value = str(address)
    direct = exact_targets.get(address_value)
    if direct is not None:
        configured.append((direct, "ip", address_value))
        return configured
    for network, target in networks:
        if address in network:
            configured.append((target, "ip", address_value))
            break
    return configured


def _matching_ports(document, criteria, rules, parser_config):
    # Requested-name filters can use the open ports explicitly recorded for
    # that name. Service filters still need evidence from each matched port.
    direct_fields = DIRECT_PORT_FIELDS
    if not query_can_prove_port(criteria):
        direct_fields = direct_fields | REQUESTED_HOST_FIELDS
    body = document.get("body") or {}
    ports = set()
    for port in body.get("ports") or []:
        state = port.get("state") or {}
        try:
            number = int(port.get("portid"))
        except (TypeError, ValueError):
            continue
        if (
            str(port.get("protocol") or "tcp").lower() != "tcp"
            or not 1 <= number <= 65535
            or state.get("state") != "open"
        ):
            continue
        scoped = dict(document)
        scoped["body"] = dict(body, ports=[port])
        parsed = parse_json(scoped, parser_config, tag_rules=[])
        if parsed:
            parsed["tag"] = _port_tags(parsed, rules)
            matched, has_port_evidence = _match_with_port_evidence(
                parsed, criteria, set(parsed.get("tag", [])), direct_fields
            )
            if matched and has_port_evidence:
                ports.add(number)
    return ports


def _selection_context():
    targets = db.session.query(Targets.id, Targets.value).all()
    exact = {
        value.strip().rstrip(".").lower(): target_id for target_id, value in targets
    }
    networks = []
    for target_id, value in targets:
        try:
            networks.append((ipaddress.ip_network(value, strict=False), target_id))
        except ValueError:
            continue
    networks.sort(key=lambda item: item[0].prefixlen, reverse=True)
    rules = compile_tag_rule_records(
        db.session.query(TagRules).filter(TagRules.active.is_(True)).all()
    )
    return exact, networks, rules


def filtered_candidates(
    indexer,
    meili_index,
    criteria,
    from_ts,
    to_ts,
    parser_config,
    timeout=None,
    *,
    selection=None,
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Yield validated configured targets and exact matching TCP port sets."""
    exact, networks, rules = (
        selection if selection is not None else _selection_context()
    )
    for uid in matching_observations(
        indexer, criteria, from_ts, to_ts, timeout=timeout
    ):
        document = meili_index.get_document(uid)
        document = vars(document) if not isinstance(document, dict) else document
        targets = _configured_targets(document, exact, networks)
        if not targets:
            continue
        ports = _matching_ports(document, criteria, rules, parser_config)
        if ports:
            for target in targets:
                yield (*target, ports)


def first_scan_candidate(
    indexer, meili_index, criteria, from_ts, to_ts, parser_config, timeout=10
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Validate one usable target+port pair without materializing full results."""
    return next(
        filtered_candidates(
            indexer,
            meili_index,
            criteria,
            from_ts,
            to_ts,
            parser_config,
            timeout=timeout,
        ),
        None,
    )


def _merge_work(cycle, target_id, kind, value, ports, scan_family=None):
    row = (
        db.session.query(FilteredScanTargets)
        .filter_by(
            cycle_id=cycle.id,
            target_kind=kind,
            target_value=value,
            scan_family=scan_family,
        )
        .one_or_none()
    )
    completed = (
        {int(port) for port in (row.completed_ports or "").split(",") if port}
        if row
        else set()
    )
    pending = (
        {int(port) for port in row.ports.split(",") if port}
        if row and row.status == "pending"
        else set()
    )
    merged = sorted((ports | pending) - completed)
    if row is None:
        row = FilteredScanTargets(
            cycle=cycle,
            configured_target_id=target_id,
            target_kind=kind,
            target_value=value,
            scan_family=scan_family,
            ports=",".join(map(str, merged)),
        )
        db.session.add(row)
    else:
        if merged:
            row.ports = ",".join(map(str, merged))
            row.status = "pending"
            row.job = None


def _reset_unpublished_work(cycle):
    """Discard partial extraction output while retaining completed scan work."""
    pending = db.session.query(FilteredScanTargets).filter_by(
        cycle_id=cycle.id, status="pending", job_id=None
    )
    pending.filter(
        FilteredScanTargets.completed_ports.isnot(None),
        FilteredScanTargets.completed_ports != "",
    ).update(
        {
            FilteredScanTargets.ports: FilteredScanTargets.completed_ports,
            FilteredScanTargets.status: "completed",
        },
        synchronize_session=False,
    )
    pending.delete(synchronize_session=False)


def _lock_preparation(cycle_id, revision=None):
    """Start a short write transaction and verify that the cycle still owns it."""
    connection = db.session.connection()
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    query = (
        db.session.query(ScanProfileCycles, ScanProfiles)
        .join(ScanProfileCycles.scanprofile)
        .filter(ScanProfileCycles.id == cycle_id, ScanProfileCycles.status == "running")
    )
    if revision is not None:
        query = query.filter(
            ScanProfileCycles.filter_revision == revision,
            ScanProfileCycles.preparation_status == "extracting",
        )
    current = query.with_for_update().one_or_none()
    if current is None:
        db.session.rollback()
        return None
    cycle, profile = current
    if not profile.scan_enabled or profile.filter_revision != cycle.filter_revision:
        cycle.preparation_status = "cancelled"
        db.session.commit()
        return None
    return current


def _finish_preparation(cycle_id, revision, status):
    current = _lock_preparation(cycle_id, revision)
    if current is not None:
        cycle, _profile = current
        cycle.preparation_status = status
        db.session.commit()


def _write_preparation_batches(cycle_id, revision, candidates, scan_tool):
    accepted = 0
    while batch := list(islice(candidates, PREPARATION_BATCH_SIZE)):
        current = _lock_preparation(cycle_id, revision)
        if current is None:
            return accepted
        cycle, _profile = current
        for target_id, kind, value, ports in batch:
            if scan_tool == "masscan":
                families = (
                    ("ipv4", "ipv6")
                    if kind == "fqdn"
                    else (
                        "ipv4" if ipaddress.ip_address(value).version == 4 else "ipv6",
                    )
                )
            else:
                families = (None,)
            for family in families:
                _merge_work(cycle, target_id, kind, value, ports, scan_family=family)
        db.session.commit()
        accepted += len(batch)
    _finish_preparation(cycle_id, revision, "ready" if accepted else "no_matches")
    return accepted


def _start_preparation(cycle_id):
    current = _lock_preparation(cycle_id)
    if current is None:
        return None
    cycle, profile = current
    from app.views import KVSearchView  # pylint: disable=import-outside-toplevel

    criteria, valid, error = KVSearchView().parse_query(
        cycle.filter_query, allow_since_directive=True
    )
    if not valid:
        cycle.preparation_status = "error"
        db.session.commit()
        raise ValueError(error or "Invalid filtered scan query")

    # A previous extraction may have committed a partial candidate set before
    # failing. Rebuild that unpublished set from the search results so obsolete
    # ports cannot leak into the jobs staged after preparation completes.
    _reset_unpublished_work(cycle)
    preparation = (
        cycle.filter_revision,
        criteria,
        cycle.filter_from_ts,
        cycle.filter_to_ts,
        profile.scan_tool,
    )
    cycle.preparation_status = "extracting"
    db.session.commit()
    return preparation


@pinned_read
def prepare_cycle(cycle_id, meili_index):
    """Extract each batch outside SQL and commit it before resuming backend reads."""
    db.session.rollback()
    try:
        preparation = _start_preparation(cycle_id)
        if preparation is None:
            return 0
        revision, criteria, from_ts, to_ts, scan_tool = preparation
        selection = _selection_context()
        db.session.rollback()

        parser_config = db.app.config
        try:
            indexer = KVrocksIndexer(
                parser_config["KVROCKS_HOST"], parser_config["KVROCKS_PORT"]
            )
            candidates = filtered_candidates(
                indexer,
                meili_index,
                criteria,
                from_ts,
                to_ts,
                parser_config,
                timeout=None,
                selection=selection,
            )
            return _write_preparation_batches(cycle_id, revision, candidates, scan_tool)
        except (MeilisearchError, RedisError, OSError):
            db.session.rollback()
            _finish_preparation(cycle_id, revision, "retry")
            raise
    except SQLAlchemyError:
        db.session.rollback()
        raise


def start_due_cycle(profile, search_view):
    """Create persisted preparation state when profile frequency permits."""
    now = utcnow_naive()
    previous = (
        db.session.query(ScanProfileCycles)
        .filter_by(scanprofile_id=profile.id)
        .order_by(ScanProfileCycles.started_at.desc(), ScanProfileCycles.id.desc())
        .first()
    )
    if previous and previous.status == "running":
        return None
    if previous and profile.scan_cycle_minutes:
        due = previous.started_at + timedelta(minutes=profile.scan_cycle_minutes)
        if now < due:
            return None
    # pylint: disable=protected-access
    days, _, _ = search_view._extract_since_days(profile.search_query)
    window, _, _ = search_view._resolve_since_time_range(days or 30)
    cycle = ScanProfileCycles(
        scanprofile=profile,
        started_at=now,
        status="running",
        max_target_id=0,
        filter_revision=profile.filter_revision,
        preparation_status="pending",
        filter_query=profile.search_query,
        filter_from_ts=window["from_ts"],
        filter_to_ts=window["to_ts"],
    )
    db.session.add(cycle)
    db.session.flush()
    profile.current_cycle_id = cycle.id
    db.session.commit()
    return cycle
