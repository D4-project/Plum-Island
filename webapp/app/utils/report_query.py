"""Offline report-query validation using the search parser and tag library."""

import ipaddress
import shlex

from plum_antibodies import TagValidationError, validate_tag


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


def _validate_and_placement(tokens):
    """Reject dangling explicit AND tokens the search parser otherwise drops."""
    predicates = [
        token
        for token in tokens
        if token.lower() != "debug" and not token.lower().startswith("since:")
    ]
    for position, token in enumerate(predicates):
        if token.upper() == "AND":
            before = predicates[position - 1].upper() if position else ""
            after = (
                predicates[position + 1].upper()
                if position + 1 < len(predicates)
                else ""
            )
            if (
                not before
                or before in {"AND", "OR", "NOT"}
                or not after
                or after in {"AND", "OR"}
            ):
                raise ValueError("AND must join two search terms")


def validate_report_query(query, parser):
    """Return a valid query, canonicalizing tags only; perform no backend I/O.

    ``parser`` is the existing KVSearchView parser, not a second query grammar.
    The extra checks reject empty/ill-typed predicates and dangling AND tokens
    which the interactive parser historically accepts.
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
    tokens = shlex.split(query)
    _validate_and_placement(tokens)
    if not groups or any(not group for group in groups):
        raise ValueError("Each OR group requires a search term")
    for group in groups:
        for field, values in group.items():
            for value in values:
                _validate_value(field, value)

    # Canonical library normalization must also reach the stored query, so
    # accepted legacy tag:tag:... values do not silently search a different tag.
    normalized = []
    changed = False
    for token in tokens:
        if token.lower().startswith("tag:"):
            replacement = "tag:" + validate_tag(token.split(":", 1)[1])
            changed |= replacement != token
            token = replacement
        normalized.append(token)
    return shlex.join(normalized) if changed else query
