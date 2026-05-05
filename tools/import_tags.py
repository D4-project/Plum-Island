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
TAG_FLUSH_BATCH_SIZE = 1000


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
        "--flush-tag",
        help=(
            "Delete one tag from Kvrocks tag indexes and exit. "
            "Accepts 'value' or 'tag:value'."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the final summary and errors.",
    )
    args = parser.parse_args()
    if args.flush_db and args.flush_tag:
        parser.error("--flush_db cannot be combined with --flush-tag")
    return args


def normalize_flush_tag(raw_tag):
    """
    Normalize a CLI tag value to the stored Kvrocks tag value.
    """
    tag = str(raw_tag or "").strip().lower()
    if tag.startswith("tag:"):
        tag = tag.split(":", 1)[1].strip()
    if not tag:
        raise ValueError("Tag name is required")
    return tag


def flush_kvrocks_tag(indexer, raw_tag, dry_run=False, quiet=False):
    """
    Delete one Kvrocks tag index and remove its inverse UID references.
    """
    tag = normalize_flush_tag(raw_tag)
    tag_key = f"tag:{tag}"
    uid_count = indexer.r.scard(tag_key)

    summary = {
        "tag": tag,
        "tag_uids": uid_count,
        "tag_key_deleted": 0,
        "inverse_removed": 0,
        "inverse_deleted": 0,
    }

    if dry_run:
        if not quiet:
            print(f"WOULD_DELETE {tag_key} uids={uid_count}")
        return summary

    batch = []

    def flush_batch(uid_batch):
        remove_pipe = indexer.r.pipeline(transaction=False)
        for uid in uid_batch:
            remove_pipe.srem(f"tags:{uid}", tag)
        removed = sum(remove_pipe.execute())

        count_pipe = indexer.r.pipeline(transaction=False)
        for uid in uid_batch:
            count_pipe.scard(f"tags:{uid}")
        counts = count_pipe.execute()

        empty_keys = [
            f"tags:{uid}"
            for uid, remaining_count in zip(uid_batch, counts)
            if remaining_count == 0
        ]
        deleted = indexer.r.delete(*empty_keys) if empty_keys else 0
        return removed, deleted

    for uid in indexer.r.sscan_iter(tag_key, count=TAG_FLUSH_BATCH_SIZE):
        batch.append(uid)
        if len(batch) >= TAG_FLUSH_BATCH_SIZE:
            removed, deleted = flush_batch(batch)
            summary["inverse_removed"] += removed
            summary["inverse_deleted"] += deleted
            batch.clear()

    if batch:
        removed, deleted = flush_batch(batch)
        summary["inverse_removed"] += removed
        summary["inverse_deleted"] += deleted

    summary["tag_key_deleted"] = indexer.r.delete(tag_key)
    if not quiet:
        print(
            f"DELETE {tag_key} "
            f"uids={summary['tag_uids']} "
            f"inverse_removed={summary['inverse_removed']} "
            f"inverse_deleted={summary['inverse_deleted']}"
        )
    return summary


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
    flush_tag = getattr(args, "flush_tag", None)
    yaml_files = [] if args.flush_db or flush_tag else get_yaml_files(args)

    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel
    from app.utils.kvrocks import KVrocksIndexer  # pylint: disable=import-outside-toplevel
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
        "tag": "",
        "tag_uids": 0,
        "tag_key_deleted": 0,
        "inverse_removed": 0,
        "inverse_deleted": 0,
    }

    with app.app_context():
        if flush_tag:
            indexer = KVrocksIndexer(
                app.config["KVROCKS_HOST"],
                app.config["KVROCKS_PORT"],
            )
            summary.update(
                flush_kvrocks_tag(
                    indexer,
                    flush_tag,
                    dry_run=args.dry_run,
                    quiet=args.quiet,
                )
            )
            return summary

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
                if not args.dry_run:
                    new_rule = TagRules(
                        name=name,
                        active=True,
                        description=normalized["description"],
                        query=normalized["query"],
                        tags=tags_text,
                        created_at=source_version,
                        updated_at=source_version,
                    )
                    db.session.add(new_rule)
                    db.session.flush()
                    if not args.quiet:
                        print(f"INSERT {name} id={new_rule.id} version={version_label}")
                elif not args.quiet:
                    print(f"WOULD_INSERT {name} version={version_label}")
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
    if args.flush_tag:
        print(
            "Tag Kvrocks flush complete: "
            f"tag={summary['tag']} "
            f"uids={summary['tag_uids']} "
            f"inverse_removed={summary['inverse_removed']} "
            f"inverse_deleted={summary['inverse_deleted']} "
            f"tag_key_deleted={summary['tag_key_deleted']} "
            f"dry_run={args.dry_run}"
        )
    elif args.flush_db:
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
