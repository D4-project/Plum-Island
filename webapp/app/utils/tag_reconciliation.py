"""Rule snapshots, coverage and incremental contribution evaluation.

No Flask or scheduler import at module load: the supervisor and CLI use the same
pure planning functions. Durable control records live alongside the Kvrocks
index they describe, not in a browser process or temporary status file.
"""

import hashlib
import json
from pathlib import Path

try:
    from .index_revision_compat import compatible_code_revision
    from .search_query import iter_criteria
    from .tagrules import (
        analyze_header_dependencies,
        compile_tag_rule_definition,
        document_matches_criteria_groups,
        parse_tags_text,
    )
    from .result_parser import has_indexed_tls_certificate
except ImportError:
    from index_revision_compat import compatible_code_revision
    from search_query import iter_criteria
    from tagrules import (
        analyze_header_dependencies,
        compile_tag_rule_definition,
        document_matches_criteria_groups,
        parse_tags_text,
    )
    from result_parser import has_indexed_tls_certificate


def fingerprint(value):
    """Hash canonical structured input with an explicit terminator."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "|"
    return hashlib.sha3_512(encoded.encode("utf-8")).hexdigest()


def code_revision():
    """Prevent resuming frozen work under a different parser/evaluator build."""
    root = Path(__file__).parent
    revision = fingerprint(
        {
            name: (root / name).read_text(encoding="utf-8")
            for name in (
                "result_parser.py",
                "domains.py",
                "tagrules.py",
                "search_query.py",
                "tag_reconciliation.py",
                "index_reconciliation.py",
                "index_generations.py",
                "kvrocks.py",
                "mutils.py",
            )
        }
    )
    return compatible_code_revision(revision)


def rule_snapshot(records, config, headers):
    """Describe executable inputs only; names and timestamps do not invalidate."""
    rules = {
        str(row.uuid): {
            "query": str(row.query).strip(),
            "tags": sorted(parse_tags_text(row.tags)),
        }
        for row in records
        if row.active
    }
    snapshot = {
        "rules": rules,
        "parser": {
            "TLDADD": sorted(config.get("TLDADD", [])),
            "HTTP_HEADER_COLLECTION": {
                str(row.header_name).strip().lower(): bool(row.collect_value)
                for row in headers
            },
        },
        "code": code_revision(),
    }
    snapshot["revision"] = fingerprint(snapshot)
    return snapshot


class RulePlan:
    """Compile a frozen rule set and its explicit tag dependency graph."""

    def __init__(self, snapshot, previous=None):
        self.snapshot = snapshot
        self.rules = {}
        self.dependencies = {}
        self.order = []
        producers = {}
        for rule_id, rule in snapshot["rules"].items():
            try:
                self.rules[rule_id] = compile_tag_rule_definition(
                    rule_id, "", rule["query"], rule["tags"]
                )
            except ValueError as error:
                raise ValueError(f"Invalid rule {rule_id}: {error}") from error
            for tag in rule["tags"]:
                producers.setdefault(tag, set()).add(rule_id)
        for rule_id, rule in self.rules.items():
            dependencies = set()
            for group in iter_criteria(rule["criteria_groups"]):
                for field, values in group.items():
                    base, _, modifier = field.removeprefix("!").partition(".")
                    if base != "tag":
                        continue
                    if modifier:
                        raise ValueError(
                            "Tag rule dependencies require exact tag predicates"
                        )
                    for value in values if isinstance(values, list) else [values]:
                        dependencies.update(producers.get(value, set()))
            self.dependencies[rule_id] = dependencies
        for rule_id in self.rules:
            self._visit(rule_id, set())
        self._find_changed(previous)
        if not self.covered({"code": snapshot["code"], "parser": snapshot["parser"]}):
            raise ValueError(
                "Required HTTP headers are not enabled in the frozen collection configuration"
            )

    def _find_changed(self, previous):
        """Invalidate changed producers and their transitive dependents."""
        before = (previous or {}).get("rules", {})
        self.changed = {
            rule_id
            for rule_id, rule in self.snapshot["rules"].items()
            if before.get(rule_id) != rule
        }
        if previous and previous.get("code") != self.snapshot["code"]:
            self.changed = set(self.rules)
        # Removed producers can change the truth of positive AND NOT predicates.
        removed_tags = {
            tag
            for rule_id, rule in before.items()
            if self.snapshot["rules"].get(rule_id) != rule
            for tag in rule["tags"]
        }
        for rule_id, rule in self.rules.items():
            for group in iter_criteria(rule["criteria_groups"]):
                if any(
                    field.removeprefix("!").split(".")[0] == "tag"
                    and bool(
                        set(values if isinstance(values, list) else [values])
                        & removed_tags
                    )
                    for field, values in group.items()
                ):
                    self.changed.add(rule_id)
        for rule_id in self.order:
            if self.dependencies[rule_id] & self.changed:
                self.changed.add(rule_id)

    def _visit(self, rule_id, visiting):
        if rule_id in visiting:
            raise ValueError("Cyclic tag rule dependencies cannot be reconciled")
        if rule_id in self.order:
            return
        visiting.add(rule_id)
        for dependency in sorted(self.dependencies[rule_id]):
            self._visit(dependency, visiting)
        visiting.remove(rule_id)
        self.order.append(rule_id)

    def covered(self, coverage):
        """A missing value is meaningful only under a compatible coverage profile."""
        if not coverage or coverage.get("code") != self.snapshot["code"]:
            return False
        previous = coverage["parser"]
        current = self.snapshot["parser"]
        if previous.get("TLDADD") != current.get("TLDADD"):
            return False
        headers = previous.get("HTTP_HEADER_COLLECTION", {})
        if headers != current.get("HTTP_HEADER_COLLECTION", {}):
            return False
        for rule in self.rules.values():
            needed = analyze_header_dependencies(rule["criteria_groups"])
            if needed["ambiguous"]:
                # Exact collection cannot prove arbitrary header-name patterns.
                raise ValueError(
                    "Ambiguous HTTP header dependency requires explicit collection"
                )
            for name, needs_value in needed["exact"].items():
                if name not in headers or (needs_value and not headers[name]):
                    return False
        return True

    def evaluate(self, document, previous=None, force=False):
        """Retain unchanged contributions and evaluate changed rules in DAG order."""
        force = force or previous is None
        previous = previous or {}
        contributions = {}
        tags = {"proto:tls"} if has_indexed_tls_certificate(document) else set()
        for rule_id in self.order:
            rule = self.rules[rule_id]
            if force or rule_id in self.changed:
                matched = document_matches_criteria_groups(
                    dict(document, tag=sorted(tags)), rule["criteria_groups"]
                )
                values = rule["tags"] if matched else []
            else:
                values = previous.get(rule_id, [])
            if values:
                contributions[rule_id] = values
            tags.update(values)
        return sorted(tags), contributions
