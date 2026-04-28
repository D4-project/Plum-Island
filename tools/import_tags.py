#!/usr/bin/env python3
"""
Import YAML tag rules into the Flask database.

Conflict policy:
- New rules are inserted.
- Existing rules are replaced only when the YAML version is older than the
  database version.
- A YAML file without a version is considered older than any database row.
"""

import argparse
import logging
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = BASE_DIR / "webapp"
DEFAULT_TAGS_DIR = WEBAPP_DIR / "tags"
MISSING_VERSION_TIME = datetime(1970, 1, 1)


def parse_args():
    """
    Parse CLI arguments before importing the Flask app.
    """
    parser = argparse.ArgumentParser(
        description="Import YAML tag rules into the Plum Island DB."
    )
    parser.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help=f"Directory containing tag YAML files. Default: {DEFAULT_TAGS_DIR}",
    )
    parser.add_argument(
        "--tags-file",
        help="Import only one tag YAML file instead of scanning --tags-dir.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and print planned changes without writing to the DB.",
    )
    parser.add_argument(
        "--flush_db",
        action="store_true",
        help="Delete all tag rules from the SQLite DB and exit.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the final summary and errors.",
    )
    return parser.parse_args()


def parse_yaml_version(raw_version):
    """
    Parse a YAML version timestamp into a naive UTC-ish datetime.

    YAML files without a timestamp deliberately get an old sentinel value so
    they win over existing DB rows under the "keep oldest" policy.
    """
    if raw_version in (None, ""):
        return MISSING_VERSION_TIME, False

    value = str(raw_version).strip()
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y%m%d%H%M%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt), True
        except ValueError:
            pass

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Invalid version timestamp: {value}") from error

    if parsed.tzinfo is not None and parsed.tzinfo.utcoffset(parsed) is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.replace(tzinfo=None), True


def load_yaml_rule(path):
    """
    Load a YAML file and return its raw payload plus parsed source version.
    """
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8") or "")
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML: {error}") from error

    if not isinstance(payload, dict):
        raise ValueError("Tag rule YAML must be a mapping")

    source_version, has_version = parse_yaml_version(payload.get("version"))
    return payload, source_version, has_version


def iter_yaml_files(tags_dir):
    """
    Iterate YAML files from a tag directory.
    """
    for path in sorted(tags_dir.glob("*.yaml")):
        if path.is_file():
            yield path


def get_yaml_files(args):
    """
    Return the YAML files selected by CLI arguments.
    """
    if args.tags_file:
        tags_file = Path(args.tags_file).resolve()
        if not tags_file.is_file():
            raise FileNotFoundError(f"Tag YAML file not found: {tags_file}")
        return [tags_file]

    tags_dir = Path(args.tags_dir).resolve()
    if not tags_dir.is_dir():
        raise FileNotFoundError(f"Tags directory not found: {tags_dir}")
    return list(iter_yaml_files(tags_dir))


def should_replace(source_version, db_rule):
    """
    Return True when the YAML rule is older than the DB row.
    """
    db_version = db_rule.updated_at or db_rule.created_at or datetime.max
    return source_version < db_version


def import_rules(args):
    """
    Import all YAML rules according to the version policy.
    """
    yaml_files = [] if args.flush_db else get_yaml_files(args)

    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel
    from app.utils.tagrules import (  # pylint: disable=import-outside-toplevel
        compile_tag_rule_definition,
        format_tags_text,
        parse_tag_rule_yaml,
    )

    summary = {
        "deleted": 0,
        "inserted": 0,
        "updated": 0,
        "kept_db": 0,
        "unchanged": 0,
        "skipped": 0,
    }

    with app.app_context():
        if args.flush_db:
            summary["deleted"] = db.session.query(TagRules).count()
            if not args.quiet:
                action = "WOULD_DELETE" if args.dry_run else "DELETE"
                print(f"{action} tagrules count={summary['deleted']}")
            if not args.dry_run:
                db.session.query(TagRules).delete(synchronize_session=False)
                db.session.commit()
            else:
                db.session.rollback()
            return summary

        for yaml_file in yaml_files:
            name = yaml_file.stem
            try:
                payload, source_version, has_version = load_yaml_rule(yaml_file)
                normalized = parse_tag_rule_yaml(yaml_file.read_text(encoding="utf-8"))
                compile_tag_rule_definition(
                    name,
                    normalized["description"],
                    normalized["query"],
                    normalized["tags"],
                )
            except Exception as error:
                summary["skipped"] += 1
                print(f"SKIP {yaml_file.name}: {error}", file=sys.stderr)
                continue

            existing = db.session.query(TagRules).filter_by(name=name).one_or_none()
            tags_text = format_tags_text(normalized["tags"])
            version_label = payload.get("version") if has_version else "missing"

            if existing is None:
                summary["inserted"] += 1
                if not args.quiet:
                    print(f"INSERT {name} version={version_label}")
                if not args.dry_run:
                    db.session.add(
                        TagRules(
                            name=name,
                            active=True,
                            description=normalized["description"],
                            query=normalized["query"],
                            tags=tags_text,
                            created_at=source_version,
                            updated_at=source_version,
                        )
                    )
                continue

            same_content = (
                existing.description == normalized["description"]
                and existing.query == normalized["query"]
                and existing.tags == tags_text
            )
            if same_content:
                summary["unchanged"] += 1
                continue

            if not should_replace(source_version, existing):
                summary["kept_db"] += 1
                if not args.quiet:
                    print(
                        f"KEEP_DB {name} "
                        f"yaml_version={version_label} db_updated_at={existing.updated_at}"
                    )
                continue

            summary["updated"] += 1
            if not args.quiet:
                print(
                    f"UPDATE {name} "
                    f"yaml_version={version_label} db_updated_at={existing.updated_at}"
                )
            if not args.dry_run:
                existing.description = normalized["description"]
                existing.query = normalized["query"]
                existing.tags = tags_text
                existing.updated_at = source_version

        if args.dry_run:
            db.session.rollback()
        else:
            db.session.commit()

    return summary


def main():
    """
    CLI entrypoint.
    """
    args = parse_args()
    summary = import_rules(args)
    if args.flush_db:
        print(
            "Tag DB flush complete: "
            f"deleted={summary['deleted']} "
            f"dry_run={args.dry_run}"
        )
    else:
        print(
            "Tag import complete: "
            f"inserted={summary['inserted']} "
            f"updated={summary['updated']} "
            f"kept_db={summary['kept_db']} "
            f"unchanged={summary['unchanged']} "
            f"skipped={summary['skipped']} "
            f"dry_run={args.dry_run}"
        )


if __name__ == "__main__":
    main()
