"""Quote-aware, non-distributive Boolean queries shared by search and rules."""

from dataclasses import dataclass
import shlex


@dataclass(frozen=True)
class QueryToken:
    """Retain spelling for safe report canonicalization, separate from syntax."""

    value: str
    raw: str
    kind: str


def tokenize_query(query):
    """Split unquoted parentheses; let shlex decode each literal field token."""
    tokens = []
    start = 0
    quote = None
    escaped = False
    text = query or ""

    def emit(stop):
        raw = text[start:stop]
        if raw:
            value = shlex.split(raw)[0]
            kind = value.upper() if value.upper() in {"AND", "OR", "NOT"} else "TERM"
            tokens.append(QueryToken(value, raw, kind))

    for position, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char.isspace() or char in "()":
            emit(position)
            if char in "()":
                tokens.append(QueryToken(char, char, char))
            start = position + 1
    emit(len(text))
    return tokens


@dataclass(frozen=True)
class Expression:
    """Small immutable tree; criteria retain legacy flat-group semantics."""

    kind: str
    children: tuple = ()
    fields: tuple = ()

    def criteria(self):
        """Return a fresh mutable legacy dictionary for existing consumers."""
        return {field: list(values) for field, values in self.fields}


def criteria_expression(criteria):
    """Freeze a flat group without losing field/value order."""
    return Expression(
        "criteria",
        fields=tuple(
            (field, tuple(values if isinstance(values, list) else [values]))
            for field, values in criteria.items()
        ),
    )


def combine(kind, children):
    """Avoid redundant unary nodes; never distribute AND over OR."""
    children = tuple(children)
    return children[0] if len(children) == 1 else Expression(kind, children)


def query_expression(query):
    """Accept both old flat group lists and parenthesized expression trees."""
    if isinstance(query, Expression):
        return query
    return combine("any", [criteria_expression(group) for group in query or []])


def iter_criteria(query):
    """Visit syntax leaves without expanding combinations of sibling groups."""
    node = query_expression(query)
    if node.kind == "criteria":
        yield node.criteria()
    else:
        for child in node.children:
            yield from iter_criteria(child)


def map_criteria(query, function):
    """Transform leaves while preserving explicit grouping and legacy lists."""
    if not isinstance(query, Expression):
        return [function(group) for group in query]
    if query.kind == "criteria":
        return criteria_expression(function(query.criteria()))
    return Expression(
        query.kind, tuple(map_criteria(child, function) for child in query.children)
    )


def has_positive_bound(node):
    """Every OR path must acquire positive candidates before any exclusion."""
    if node.kind == "criteria":
        return any(not field.startswith("!") for field, _ in node.fields)
    bounds = [has_positive_bound(child) for child in node.children]
    return any(bounds) if node.kind == "all" else bool(bounds) and all(bounds)


class QueryCompiler:
    """Linear-size syntax tree with at most one user-written grouping level."""

    def __init__(self, parser, tokens):
        self.parser = parser
        self.tokens = tokens
        self.position = 0

    def peek(self):
        """Return the next syntax token, or an explicit end marker."""
        return (
            self.tokens[self.position].kind
            if self.position < len(self.tokens)
            else "END"
        )

    def parse_or(self, grouped=False):
        """OR has lower precedence than explicit or implicit AND."""
        children = [self.parse_and(grouped)]
        while self.peek() == "OR":
            self.position += 1
            children.append(self.parse_and(grouped))
        return combine("any", children)

    def parse_and(self, grouped):
        """Keep consecutive field terms in a legacy group, groups as subtrees."""
        children = []
        parts = []
        expect_operand = True

        def flush():
            if parts:
                # Reuse the existing field/NOT validator, not a second grammar.
                # pylint: disable-next=protected-access
                criteria, valid, error = self.parser._parse_query_group_with_not(
                    parts, allow_negative_only=True
                )
                if not valid:
                    raise ValueError(error)
                children.append(criteria_expression(criteria))
                parts.clear()

        while self.peek() not in {"END", "OR", ")"}:
            kind = self.peek()
            if kind == "AND":
                if expect_operand:
                    raise ValueError("AND must join two search terms or groups")
                self.position += 1
                expect_operand = True
                continue
            if kind == "(":
                if grouped:
                    raise ValueError("Nested parentheses are not supported")
                flush()
                self.position += 1
                children.append(self.parse_or(grouped=True))
                if self.peek() != ")":
                    raise ValueError("Missing closing parenthesis")
                self.position += 1
            else:
                if kind == "NOT":
                    parts.append("NOT")
                    self.position += 1
                    if self.peek() != "TERM":
                        raise ValueError("NOT must be followed by a field:value term")
                parts.append(self.tokens[self.position].value)
                self.position += 1
            expect_operand = False
        if expect_operand:
            raise ValueError("Missing search term or empty group")
        flush()
        return combine("all", children)


def compile_query(parser, query, allow_since=False, allow_debug=False):
    """Validate offline; retain the old list representation for flat queries."""
    try:
        tokens = tokenize_query(query)
        for position, token in enumerate(tokens):
            if token.kind != "NOT":
                continue
            operand = tokens[position + 1] if position + 1 < len(tokens) else None
            if (
                operand is None
                or operand.kind != "TERM"
                or operand.value.lower() == "debug"
                or operand.value.lower().startswith("since:")
            ):
                raise ValueError("NOT must be followed by a field:value term")
        tokens = [
            token
            for token in tokens
            if not (allow_debug and token.value.lower() == "debug")
            and not (allow_since and token.value.lower().startswith("since:"))
        ]
        if not tokens:
            raise ValueError("Empty query")
        compiler = QueryCompiler(parser, tokens)
        expression = compiler.parse_or()
        if compiler.peek() != "END":
            raise ValueError("Unexpected closing parenthesis")
        if not has_positive_bound(expression):
            raise ValueError("Each OR branch requires a positive search term")
        if not any(token.kind == "(" for token in tokens):
            return list(iter_criteria(expression)), True, ""
        return expression, True, ""
    except ValueError as error:
        return [], False, f"Invalid query syntax: {error}"
