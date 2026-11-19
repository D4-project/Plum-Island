"""Offline report-query validation using the search parser and tag library."""

import ipaddress
import shlex

from plum_antibodies import TagValidationError, validate_tag

from .search_query import iter_criteria, tokenize_query


def _validate_value(field, value):
    """Validate typed predicates without checking whether they match data."""
    base, _, modifier = field.lstrip("!").partition(".")
    if not value.strip():
        raise ValueError(f"Missing value for {field}")
    if base in {"ip", "net", "port"} and modifier:
        raise ValueError(f"{base}: does not support modifiers in report queries")
    try:
        if base == "ip":
            ipaddress.ip_address(value)
        elif base == "net":
            if "/" not in value:
                raise ValueError("expected a CIDR prefix")
            ipaddress.ip_network(value, strict=False)
        elif base == "port":
            if (
                not value.isascii()
                or not value.isdecimal()
                or not 0 <= int(value) <= 65535
            ):
                raise ValueError("expected a port number from 0 to 65535")
        elif base == "tag":
            validate_tag(value)
    except (ValueError, TagValidationError) as error:
        raise ValueError(f"Invalid {field} value {value!r}: {error}") from error


def validate_report_query(query, parser):
    """Return a valid query, canonicalizing tags only; perform no backend I/O.

    ``parser`` is the existing KVSearchView parser, not a second query grammar.
    The extra checks reject empty/ill-typed predicates. Boolean grammar is shared.
    """
    query = str(query or "").strip()
    groups, status, error = parser.parse_query(
        query, allow_since_directive=True, allow_debug_directive=True
    )
    if not status:
        raise ValueError(
            f"{error}. Use field:value terms (ip:ADDRESS or net:CIDR for networks)."
        )
    # Reuse the search directive validator rather than duplicating its rules.
    # pylint: disable-next=protected-access
    _, status, error = parser._extract_since_days(query)
    if not status:
        raise ValueError(error)
    tokens = tokenize_query(query)
    if not groups or any(not group for group in iter_criteria(groups)):
        raise ValueError("Each OR group requires a search term")
    for group in iter_criteria(groups):
        for field, values in group.items():
            for value in values:
                _validate_value(field, value)

    # Canonical library normalization must also reach the stored query, so
    # accepted legacy tag:tag:... values do not silently search a different tag.
    normalized = []
    changed = False
    for token in tokens:
        raw = token.raw
        if token.kind == "TERM" and token.value.lower().startswith("tag:"):
            replacement = "tag:" + validate_tag(token.value.split(":", 1)[1])
            changed |= replacement != token.value
            raw = shlex.quote(replacement)
        normalized.append(raw)
    return " ".join(normalized) if changed else query
