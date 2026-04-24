"""
Helpers for YAML-backed search tag rules.
"""

import ipaddress
import logging
import re

import yaml

try:
    from .mutils import lowercase_dict
except ImportError:
    from mutils import lowercase_dict

logger = logging.getLogger("flask_appbuilder")

TAG_SPLIT_RE = re.compile(r"[\n,]+")


def normalize_tags(tags):
    """
    Normalize tag values to unique lowercase strings.
    """
    normalized = []
    seen = set()
    for tag in tags or []:
        value = str(tag).strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def parse_tags_text(tags_value):
    """
    Parse editable tag text or a YAML list into normalized tags.
    """
    if tags_value is None:
        return []
    if isinstance(tags_value, list):
        return normalize_tags(tags_value)

    chunks = []
    for part in TAG_SPLIT_RE.split(str(tags_value)):
        candidate = str(part).strip()
        if candidate:
            chunks.append(candidate)
    return normalize_tags(chunks)


def format_tags_text(tags):
    """
    Serialize tags to the editable newline-separated DB format.
    """
    normalized = parse_tags_text(tags)
    return "\n".join(normalized)


def parse_tag_rule_yaml(yaml_body):
    """
    Parse and normalize one tag rule YAML payload.
    """
    try:
        payload = yaml.safe_load(yaml_body or "")
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML: {error}") from error

    if not isinstance(payload, dict):
        raise ValueError("Tag rule YAML must be a mapping")

    description = str(payload.get("description") or "").strip()
    query = str(payload.get("query") or "").strip()
    raw_tags = payload.get("tags") or []

    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    if not isinstance(raw_tags, list):
        raise ValueError("'tags' must be a YAML list")

    tags = parse_tags_text(raw_tags)
    if not description:
        raise ValueError("Tag rule YAML requires a non-empty 'description'")
    if not query:
        raise ValueError("Tag rule YAML requires a non-empty 'query'")
    if not tags:
        raise ValueError("Tag rule YAML requires at least one tag")

    return {
        "description": description,
        "query": query,
        "tags": tags,
    }


def normalize_tag_rule_fields(description, query, tags_value):
    """
    Normalize directly editable DB fields for one tag rule.
    """
    description = str(description or "").strip()
    query = str(query or "").strip()
    tags = parse_tags_text(tags_value)
    if not description:
        raise ValueError("Tag rule requires a non-empty description")
    if not query:
        raise ValueError("Tag rule requires a non-empty search query")
    if not tags:
        raise ValueError("Tag rule requires at least one tag")
    return {
        "description": description,
        "query": query,
        "tags": tags,
        "tags_text": format_tags_text(tags),
    }


def validate_search_query(query):
    """
    Validate and compile one search query using the live parser semantics.
    """
    try:
        from ..views import KVSearchView
    except ImportError:
        from views import KVSearchView

    criteria_groups, status, msg_error = KVSearchView().parse_query(query)
    if not status:
        raise ValueError(msg_error or "Invalid search query")
    return [lowercase_dict(group) for group in criteria_groups]


def compile_tag_rule_definition(name, description, query, tags):
    """
    Compile one normalized tag rule to an in-memory structure.
    """
    return {
        "name": str(name or description or "").strip(),
        "description": str(description or "").strip(),
        "query": str(query or "").strip(),
        "tags": normalize_tags(tags),
        "criteria_groups": validate_search_query(query),
    }


def compile_tag_rule_records(records):
    """
    Compile active DB-backed tag rule rows, skipping invalid entries.
    """
    compiled_rules = []
    for record in records or []:
        try:
            compiled_rules.append(
                compile_tag_rule_definition(
                    getattr(record, "name", ""),
                    getattr(record, "description", ""),
                    getattr(record, "query", ""),
                    parse_tags_text(getattr(record, "tags", "")),
                )
            )
        except Exception as error:
            logger.warning(
                "Skipping invalid tag rule %s: %s",
                getattr(record, "name", "<unknown>"),
                error,
            )
    return compiled_rules


def _normalized_document_values(document, field):
    """
    Read one parsed-document field as lowercase comparable strings.
    """
    if field == "ip":
        values = [document.get("ip")]
    elif field == "tag":
        values = document.get("tag") or document.get("tags") or []
    else:
        values = document.get(field, [])

    if not isinstance(values, list):
        values = [values]

    normalized = []
    seen = set()
    for value in values:
        if value is None:
            continue
        candidate = str(value).strip().lower()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _document_field_matches(document, field, suffix, value):
    """
    Evaluate one field constraint against one parsed document.
    """
    value = str(value).strip().lower()
    if not value:
        return False

    if field == "net":
        ip_value = str(document.get("ip") or "").strip()
        if not ip_value:
            return False
        try:
            is_inside = ipaddress.ip_address(ip_value) in ipaddress.ip_network(
                value, strict=False
            )
        except ValueError:
            return False
        if suffix in ("not", "nt"):
            return not is_inside
        return is_inside

    candidates = _normalized_document_values(document, field)
    if suffix in ("like", "lk"):
        return any(value in candidate for candidate in candidates)
    if suffix in ("begin", "bg"):
        return any(candidate.startswith(value) for candidate in candidates)
    if suffix in ("not", "nt"):
        return value not in candidates
    return value in candidates


def document_matches_criteria_groups(document, criteria_groups):
    """
    Return True when one OR group fully matches the parsed document.
    """
    for criteria in criteria_groups or []:
        group_matches = True
        for field, values in criteria.items():
            base_field, suffix = (field.split(".", 1) + [""])[:2]
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if not _document_field_matches(document, base_field, suffix, value):
                    group_matches = False
                    break
            if not group_matches:
                break
        if group_matches:
            return True
    return False


def apply_tag_rules_to_document(parsed_doc, tag_rules=None):
    """
    Merge pre-existing document tags with matched rule tags.
    """
    merged_tags = normalize_tags(parsed_doc.get("tag") or parsed_doc.get("tags") or [])
    for compiled_rule in tag_rules or []:
        if document_matches_criteria_groups(
            parsed_doc, compiled_rule.get("criteria_groups", [])
        ):
            merged_tags.extend(compiled_rule.get("tags", []))
    return normalize_tags(merged_tags)
