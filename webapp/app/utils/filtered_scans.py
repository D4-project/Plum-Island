"""Prepare durable scan targets from historical search observations."""

import ipaddress
import logging
from datetime import timedelta

from meilisearch.errors import MeilisearchApiError, MeilisearchError
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.models import (
    ScanProfileCycles,
    ScanProfiles,
    TagRules,
    Targets,
)
from app.utils.domains import is_hostname_syntax
from app.utils.filtered_work import FilteredWorkStore
from app.utils.index_generations import pinned_read
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
from app.utils.search_existence import (
    chronological_observation_batches,
    observation_batches,
)
from app.utils.tagrules import (
    compile_tag_rule_records,
    nse_output_by_script,
)
from app.utils.timeutils import utcnow_naive

logger = logging.getLogger("flask_appbuilder")


def filter_progress(raw, cycle_id, revision):
    """Load a small status record without touching the observation index."""
    return FilteredWorkStore(raw, cycle_id, revision).counts()


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


def _page_candidates(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    indexer,
    meili_index,
    plan,
    observations,
    criteria,
    parser_config,
    selection,
    rules_holder,
):
    """Resolve one bounded observation page to configured target and port sets."""
    exact, networks, rule_records = selection
    direct_fields = DIRECT_PORT_FIELDS
    if not query_can_prove_port(criteria):
        direct_fields = direct_fields | REQUESTED_HOST_FIELDS
    proven = proven_indexed_ports(indexer.r, plan, observations, direct_fields)
    hostnames = indexer.get_requested_hostnames_for_uids(
        [uid for uid, ports in proven.items() if ports]
    )
    found = []
    for uid, ip, _predicates in observations:
        if uid in proven:
            ports = proven[uid]
            if not ports:
                continue
            targets = _configured_targets(ip, hostnames.get(uid, []), exact, networks)
        else:
            try:
                document = meili_index.get_document(uid)
            except MeilisearchApiError as error:
                if not document_not_found(error):
                    raise
                continue
            document = vars(document) if not isinstance(document, dict) else document
            names = [
                item.get("name")
                for item in (document.get("body") or {}).get("hostnames") or []
                if isinstance(item, dict) and item.get("type") == "user"
            ]
            targets = _configured_targets(document.get("ip"), names, exact, networks)
            if not targets:
                continue
            if rules_holder[0] is None:
                rules_holder[0] = compile_tag_rule_records(rule_records)
            ports = _matching_ports(document, criteria, rules_holder[0], parser_config)
        if ports:
            found.extend((*target, ports) for target in targets)
    return found


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
    selection = selection or _selection_context()
    rules_holder = [None]
    for plan, observations in observation_batches(
        indexer, criteria, from_ts, to_ts, timeout, progress=progress
    ):
        yield from _page_candidates(
            indexer,
            meili_index,
            plan,
            observations,
            criteria,
            parser_config,
            selection,
            rules_holder,
        )


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


def _finish_preparation(cycle_id, revision, status, target_count=None):
    current = _lock_preparation(cycle_id, revision)
    if current is not None:
        cycle, _profile = current
        cycle.preparation_status = status
        if target_count is not None:
            cycle.target_count = target_count
            cycle.scan_unit_count = target_count
        db.session.commit()


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

    fresh = cycle.preparation_status == "pending"
    preparation = (
        cycle.filter_revision,
        criteria,
        cycle.filter_from_ts,
        cycle.filter_to_ts,
        profile.scan_tool,
        fresh,
    )
    cycle.preparation_status = "extracting"
    db.session.commit()
    return preparation


@pinned_read
def prepare_cycle(cycle_id, meili_index):  # pylint: disable=too-many-locals
    """Collect filtered work in Kvrocks and write only cycle state to SQLite."""
    # pylint: disable=too-many-nested-blocks
    db.session.rollback()
    try:
        preparation = _start_preparation(cycle_id)
        if preparation is None:
            return 0
        revision, criteria, from_ts, to_ts, scan_tool, fresh = preparation
        selection = _selection_context()
        db.session.rollback()

        parser_config = db.app.config
        try:
            indexer = KVrocksIndexer(
                parser_config["KVROCKS_HOST"], parser_config["KVROCKS_PORT"]
            )
            store = FilteredWorkStore(indexer.raw, cycle_id, revision)
            if fresh:
                store.reset()
            store.begin(from_ts, to_ts)
            meta = store.metadata()
            rules_holder = [None]
            checked = int(meta.get("checked", 0))
            stage = meta.get("stage", "collecting")
            if stage == "collecting":
                for (
                    plan,
                    observations,
                    cursor,
                    page_size,
                ) in chronological_observation_batches(
                    indexer,
                    criteria,
                    from_ts,
                    to_ts,
                    timeout=None,
                    resume=store.checkpoint(),
                ):
                    candidates = _page_candidates(
                        indexer,
                        meili_index,
                        plan,
                        observations,
                        criteria,
                        parser_config,
                        selection,
                        rules_holder,
                    )
                    work = []
                    for target_id, kind, value, ports in candidates:
                        if scan_tool == "masscan":
                            families = (
                                ("ipv4", "ipv6")
                                if kind == "fqdn"
                                else (
                                    (
                                        "ipv4"
                                        if ipaddress.ip_address(value).version == 4
                                        else "ipv6"
                                    ),
                                )
                            )
                        else:
                            families = (None,)
                        work.extend(
                            (target_id, kind, value, ports, family)
                            for family in families
                        )
                    checked += page_size
                    store.add_candidates(work, checked, cursor)
                store.finish_collection()
            elif stage == "grouping":
                store.finish_collection()
            counts = store.counts()
            retained = counts["retained"]
            _finish_preparation(
                cycle_id,
                revision,
                "ready" if retained else "no_matches",
                target_count=retained,
            )
            return retained
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
    restart_after_migration = previous and previous.preparation_status in {
        "superseded_kvrocks",
        "legacy_sql_superseded",
    }
    if previous and profile.scan_cycle_minutes and not restart_after_migration:
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
