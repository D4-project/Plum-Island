"""Port-scoped scan evidence shared by indexing, filtering and display."""

import json

try:
    from .search_query import iter_criteria, query_expression
    from .tagrules import document_matches_criteria_groups, nse_output_by_script
    from .result_parser import has_indexed_tls_certificate
except ImportError:
    from search_query import iter_criteria, query_expression
    from tagrules import document_matches_criteria_groups, nse_output_by_script
    from result_parser import has_indexed_tls_certificate

PORT_EVIDENCE_FIELDS = {
    "tag",
    "banner",
    "service",
    "nodata",
    "http_title",
    "http_header",
    "http_headval",
    "http_favicon_path",
    "http_favicon_mmhash",
    "http_favicon_md5",
    "http_favicon_sha256",
    "http_server",
    "http_cookiename",
    "http_etag",
    "x509_issuer",
    "x509_subject",
    "x509_issuer_cn",
    "x509_subject_cn",
    "x509_san",
    "x509_md5",
    "x509_sha1",
    "x509_sha256",
}
DIRECT_PORT_FIELDS = PORT_EVIDENCE_FIELDS - {"tag"}
RULE_PORT_FIELDS = DIRECT_PORT_FIELDS | {"nse_body"}
REQUESTED_HOST_FIELDS = {"fqdn_requested", "domain_requested"}


def query_can_prove_port(criteria):
    """Return whether a positive query term identifies an observed port."""
    return any(
        field.lstrip("!").partition(".")[0] in PORT_EVIDENCE_FIELDS
        and field.lstrip("!").partition(".")[2] not in {"not", "nt"}
        for group in iter_criteria(criteria)
        for field in group
        if not field.startswith("!")
    )


def _tag_term_matches(tags, field, values):
    negate = field.startswith("!")
    _base, _, modifier = field.removeprefix("!").partition(".")
    candidates = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
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
                if not _tag_term_matches(document.get("tag", []), field, values):
                    return False
            elif not document_matches_criteria_groups(
                document, [{field: list(values)}]
            ):
                return False
        return True
    matches = (_port_query_matches(document, child) for child in node.children)
    return all(matches) if node.kind == "all" else any(matches)


def match_with_port_evidence(
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
        match_with_port_evidence(document, child, proven_tags, direct_fields)
        for child in node.children
    ]
    if node.kind == "all":
        return all(match for match, _ in children), any(
            match and evidence for match, evidence in children
        )
    return any(match for match, _ in children), any(
        match and evidence for match, evidence in children
    )


def port_tags(parsed, rules):
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
            matched, has_evidence = match_with_port_evidence(
                document, rule.get("criteria_groups", []), proven, RULE_PORT_FIELDS
            )
            if matched and has_evidence:
                proven.update(str(tag).lower() for tag in rule.get("tags", []))
        if len(proven) == before:
            return sorted(proven)


def read_scan_ports(client, uids):
    """Fetch small, independently versioned records in one Kvrocks pipeline."""
    if not uids:
        return {}
    pipe = client.pipeline(transaction=False)
    for uid in uids:
        pipe.get(f"scan_port:{uid}")
    return {uid: json.loads(value) for uid, value in zip(uids, pipe.execute()) if value}


def build_scan_port(source, document, plan, previous=None, *, contributions=None):
    """Build evidence for an indexed single-port observation under frozen rules."""
    if source is not None:
        ports = (source.get("body") or {}).get("ports") or ()
        if (
            not isinstance(ports, (list, tuple))
            or len(ports) != 1
            or not isinstance(ports[0], dict)
        ):
            return None
        port = ports[0]
        number = str(port.get("portid", ""))
        protocol = str(port.get("protocol") or "").lower()
        if (
            protocol not in {"tcp", "udp"}
            or not number.isascii()
            or not number.isdecimal()
        ):
            return None
        number = int(number)
        if not 1 <= number <= 65535:
            return None
        state = port.get("state") or {}
        service = port.get("service") or {}
        if not isinstance(state, dict) or not isinstance(service, dict):
            return None
        open_tcp = protocol == "tcp" and state.get("state") == "open"
        summary = {
            "port": number,
            "protocol": protocol,
            "open_tcp_port": number if open_tcp else None,
            "ttl": state.get("reason_ttl"),
            "service": service.get("name"),
        }
    elif previous is not None:
        summary = dict(previous)
    else:
        return None
    summary["revision"] = plan.snapshot["revision"]
    if summary["open_tcp_port"] is not None:
        summary["tags"], summary["nse_rules"] = _prove_tags(
            source, document, plan, previous, contributions
        )
    else:
        summary.update(tags=[], nse_rules=[])
    return summary


def _prove_tags(source, document, plan, previous, contributions):
    """Keep existing NSE proof through unrelated fast retags without reading raw text."""
    proof = {"proto:tls"} if has_indexed_tls_certificate(document) else set()
    nse_proof = []
    previous_nse = set((previous or {}).get("nse_rules", []))
    parsed = dict(document, tag=sorted(proof))
    if source is not None and plan.nse_body_rules:
        parsed["nse_body"] = nse_output_by_script(source)
    for rule_id in plan.order:
        if contributions is not None and rule_id not in contributions:
            continue
        rule = plan.rules[rule_id]
        uses_nse = rule_id in plan.nse_body_rules
        if uses_nse and source is None:
            justified = rule_id in previous_nse and rule_id not in plan.changed
        else:
            justified = all(
                match_with_port_evidence(
                    parsed, rule["criteria_groups"], proof, RULE_PORT_FIELDS
                )
            )
        if justified:
            proof.update(rule["tags"])
            parsed["tag"] = sorted(proof)
            if uses_nse:
                nse_proof.append(rule_id)
    return sorted(proof), nse_proof


def queue_scan_port(pipe, uid, summary):
    """Write or clear the auxiliary record with the associated capture tags."""
    key = f"scan_port:{uid}"
    if summary is None:
        pipe.delete(key)
    else:
        pipe.set(key, json.dumps(summary, separators=(",", ":")))


def indexed_nodata_ports(client, uids):
    """Recover an open TCP port directly from existing single-port indexes."""
    if not uids:
        return {}
    pipe = client.pipeline(transaction=False)
    for uid in uids:
        pipe.smembers(f"port_protocols:{uid}")
        pipe.smembers(f"nodatas:{uid}")
    values = pipe.execute()
    summaries = {}
    for uid, protocols, nodata in zip(uids, values[::2], values[1::2]):
        if len(protocols) == 1:
            transport, _, port = next(iter(protocols)).partition("/")
            if (
                transport in {"tcp", "udp"}
                and port in nodata
                and port.isascii()
                and port.isdecimal()
            ):
                number = int(port)
                if 1 <= number <= 65535:
                    summaries[uid] = {
                        "open_tcp_port": number if transport == "tcp" else None,
                        "tags": [],
                    }
    return summaries


def indexed_port_matches(plan, predicates, summary, direct_fields):
    """Keep the matching Boolean branch and any positive port evidence together."""
    if plan.kind == "term":
        field, values = plan.fields[0]
        base, _, modifier = field.partition(".")
        matched = predicates[plan]
        if base == "tag":
            matched = matched and _tag_term_matches(
                summary.get("tags", []), field, values
            )
        return matched, matched and (
            base in direct_fields or base == "tag"
        ) and modifier not in {"not", "nt"}
    if plan.kind == "not":
        return not predicates[plan.children[0]], False
    children = [
        indexed_port_matches(child, predicates, summary, direct_fields)
        for child in plan.children
    ]
    combine = all if plan.kind == "all" else any
    return combine(match for match, _ in children), any(
        match and evidence for match, evidence in children
    )


def proven_indexed_ports(client, plan, observations, direct_fields):
    """Return ports for covered UIDs. Missing observations need raw JSON."""
    uids = [uid for uid, _ip, _predicates in observations]
    summaries = read_scan_ports(client, uids)
    for_nodata = [
        uid
        for uid, _ip, predicates in observations
        if uid not in summaries
        and any(
            hit and term.fields[0][0] == "nodata" for term, hit in predicates.items()
        )
        and not any(term.fields[0][0].partition(".")[0] == "tag" for term in predicates)
    ]
    summaries.update(indexed_nodata_ports(client, for_nodata))
    result = {}
    for uid, _ip, predicates in observations:
        summary = summaries.get(uid)
        if summary is None:
            continue
        port = summary.get("open_tcp_port")
        result[uid] = set()
        if port and all(indexed_port_matches(plan, predicates, summary, direct_fields)):
            result[uid].add(port)
    return result
