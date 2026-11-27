"""Prepare durable scan targets from historical search observations."""

import ipaddress
import logging
import json
import time
from datetime import timedelta
from itertools import islice

from meilisearch.errors import MeilisearchApiError, MeilisearchError
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
from app.utils.index_generations import CONTROL, pinned_read
from app.utils.index_source_recovery import document_not_found
from app.utils.kvrocks import KVrocksIndexer
from app.utils.result_parser import parse_json
from app.utils.scan_ports import (
    DIRECT_PORT_FIELDS,
    REQUESTED_HOST_FIELDS,
    match_with_port_evidence,
    port_tags,
    proven_indexed_ports,
    query_can_prove_port,
)
from app.utils.search_existence import observation_batches
from app.utils.tagrules import (
    compile_tag_rule_records,
    nse_output_by_script,
)
from app.utils.timeutils import utcnow_naive

logger = logging.getLogger("flask_appbuilder")
PREPARATION_BATCH_SIZE = 100


def _progress_key(cycle_id, revision):
    return f"{CONTROL}filtered_progress:{cycle_id}:{revision}"


def filter_progress(raw, cycle_id, revision):
    """Load a small status record without touching the observation index."""
    value = raw.get(_progress_key(cycle_id, revision))
    return (
        json.loads(value) if isinstance(value, str) else {"checked": 0, "retained": 0}
    )


class FilterProgress:
    """Publish counts outside SQLite transactions at most once per second."""

    def __init__(self, raw, cycle_id, revision):
        self.raw = raw
        self.key = _progress_key(cycle_id, revision)
        self.checked = 0
        self.retained = set()
        self.next_update = 0

    def publish(self, force=False):
        """Expire transient progress once a cycle is no longer visible."""
        now = time.monotonic()
        if force or now >= self.next_update:
            self.next_update = now + 1
            try:
                self.raw.set(
                    self.key,
                    json.dumps(
                        {"checked": self.checked, "retained": len(self.retained)}
                    ),
                    ex=86400,
                )
            except RedisError:
                # Progress is optional and a failed write must not replay committed work.
                pass

    def observations(self, count):
        """Count candidates examined by the index."""
        self.checked += count
        self.publish()


def _configured_targets(ip, hostnames, exact_targets, networks):
    """Return every configured scan identity represented by one observation."""
    configured = []
    for hostname in hostnames:
        name = str(hostname or "").strip().rstrip(".").lower()
        if is_hostname_syntax(name) and name in exact_targets:
            candidate = (exact_targets[name], "fqdn", name)
            if candidate not in configured:
                configured.append(candidate)
    try:
        address = ipaddress.ip_address(ip)
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
            str(port.get("protocol") or "").lower() != "tcp"
            or not 1 <= number <= 65535
            or state.get("state") != "open"
        ):
            continue
        scoped = dict(document)
        scoped["body"] = dict(body, ports=[port])
        parsed = parse_json(scoped, parser_config, tag_rules=[])
        if parsed:
            parsed["nse_body"] = nse_output_by_script(scoped)
            parsed["tag"] = port_tags(parsed, rules)
            matched, has_port_evidence = match_with_port_evidence(
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
    rule_records = (
        db.session.query(
            TagRules.name, TagRules.description, TagRules.query, TagRules.tags
        )
        .filter(TagRules.active.is_(True))
        .all()
    )
    return exact, networks, rule_records


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
    progress=None,
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Yield validated configured targets and exact matching TCP port sets."""
    exact, networks, rule_records = (
        selection if selection is not None else _selection_context()
    )
    rules = None
    direct_fields = DIRECT_PORT_FIELDS
    if not query_can_prove_port(criteria):
        direct_fields = direct_fields | REQUESTED_HOST_FIELDS
    for plan, observations in observation_batches(
        indexer, criteria, from_ts, to_ts, timeout, progress=progress
    ):
        proven = proven_indexed_ports(indexer.r, plan, observations, direct_fields)
        hostnames = indexer.get_requested_hostnames_for_uids(
            [uid for uid, ports in proven.items() if ports]
        )
        for uid, ip, _predicates in observations:
            if uid in proven:
                ports = proven[uid]
                if not ports:
                    continue
                targets = _configured_targets(
                    ip, hostnames.get(uid, []), exact, networks
                )
            else:
                try:
                    document = meili_index.get_document(uid)
                except MeilisearchApiError as error:
                    if not document_not_found(error):
                        raise
                    continue
                document = (
                    vars(document) if not isinstance(document, dict) else document
                )
                names = [
                    item.get("name")
                    for item in (document.get("body") or {}).get("hostnames") or []
                    if isinstance(item, dict) and item.get("type") == "user"
                ]
                targets = _configured_targets(
                    document.get("ip"), names, exact, networks
                )
                if not targets:
                    continue
                if rules is None:
                    rules = compile_tag_rule_records(rule_records)
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


def _write_preparation_batches(cycle_id, revision, candidates, scan_tool, progress):
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
        progress.retained.update((kind, value) for _, kind, value, _ in batch)
        progress.publish()
    progress.publish(force=True)
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
            progress = FilterProgress(indexer.raw, cycle_id, revision)
            progress.publish()
            candidates = filtered_candidates(
                indexer,
                meili_index,
                criteria,
                from_ts,
                to_ts,
                parser_config,
                timeout=None,
                selection=selection,
                progress=progress.observations,
            )
            return _write_preparation_batches(
                cycle_id, revision, candidates, scan_tool, progress
            )
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
