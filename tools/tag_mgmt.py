#!/usr/bin/env python3
"""
Manage Plum Island tag rules and tag indexes.

Default behavior is read-only: running this file without a subcommand prints
this help and exits.
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
TOOLS_CONFIG = BASE_DIR / "tools" / "config.yaml"
MISSING_VERSION_TIME = datetime(1970, 1, 1)
TAG_FLUSH_BATCH_SIZE = 1000
MAX_BATCH_SIZE = 1000


def build_parser():
    """
    Build the command parser without importing Flask runtime modules.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Manage tag YAML import, DB rules, and Kvrocks tag indexes. "
            "Without a subcommand, this command only prints this help."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    import_parser = subparsers.add_parser(
        "import",
        help="Import YAML tag rules into the SQLite DB.",
    )
    import_parser.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help=f"Directory containing tag YAML files. Default: {DEFAULT_TAGS_DIR}",
    )
    import_parser.add_argument(
        "--tags-file",
        help="Import only one tag YAML file instead of scanning --tags-dir.",
    )
    import_parser.add_argument(
        "--id",
        dest="rule_id",
        type=int,
        help="Import the YAML rule matching an existing Tag Rule id.",
    )
    import_parser.add_argument(
        "--all",
        action="store_true",
        help="Import every YAML rule from --tags-dir.",
    )
    import_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and print planned changes without writing to the DB.",
    )
    import_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the final summary and errors.",
    )

    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete tag rules from the SQLite DB.",
    )
    delete_parser.add_argument(
        "--id",
        dest="rule_id",
        type=int,
        help="Delete one existing Tag Rule by id.",
    )
    delete_parser.add_argument(
        "--tags-file",
        help="Delete the DB tag rule matching this YAML filename stem.",
    )
    delete_parser.add_argument(
        "--all",
        action="store_true",
        help="Delete every DB tag rule.",
    )
    delete_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned deletion without writing to the DB.",
    )
    delete_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the final summary and errors.",
    )

    flush_tag_parser = subparsers.add_parser(
        "flush-tag",
        help="Delete one tag from Kvrocks tag indexes.",
    )
    flush_tag_parser.add_argument(
        "tag",
        help="Tag value to delete. Accepts 'value' or 'tag:value'.",
    )
    flush_tag_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned deletion without writing to Kvrocks.",
    )
    flush_tag_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the final summary and errors.",
    )

    reindex_parser = subparsers.add_parser(
        "reindex",
        help="Recompute Kvrocks tags from Meilisearch documents.",
    )
    reindex_parser.add_argument(
        "rule_id",
        nargs="?",
        type=int,
        help="Existing Tag Rule id used to trigger the reindex.",
    )
    reindex_parser.add_argument(
        "--allrules",
        action="store_true",
        help="Reindex tags using all active Tag Rules in one pass.",
    )
    reindex_parser.add_argument(
        "--batch-size",
        type=int,
        default=MAX_BATCH_SIZE,
        help=f"Documents per Meili page and Kvrocks flush (max {MAX_BATCH_SIZE}).",
    )
    reindex_parser.add_argument(
        "--flush",
        action="store_true",
        help="Delete all existing Kvrocks tag indexes before recomputing them.",
    )

    list_parser = subparsers.add_parser(
        "list-tags",
        help="List distinct tag values currently indexed in Kvrocks.",
    )
    list_parser.add_argument(
        "--batch-size",
        type=int,
        default=MAX_BATCH_SIZE,
        help=f"Kvrocks scan batch size (max {MAX_BATCH_SIZE}).",
    )

    return parser


def parse_args(argv=None):
    """
    Parse CLI arguments and keep the no-subcommand path read-only.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return None
    if args.command == "reindex":
        has_rule_id = args.rule_id is not None
        if has_rule_id == bool(args.allrules):
            parser.error("reindex requires either rule_id or --allrules")
    if args.command == "import":
        selectors = [
            bool(args.all),
            args.rule_id is not None,
            bool(args.tags_file),
        ]
        if sum(selectors) > 1:
            parser.error("import accepts only one of --all, --id, or --tags-file")
    if args.command == "delete":
        selectors = [
            bool(args.all),
            args.rule_id is not None,
            bool(args.tags_file),
        ]
        if sum(selectors) > 1:
            parser.error("delete accepts only one of --all, --id, or --tags-file")
    return args


def legacy_import_args(argv=None):
    """
    Parse the old import_tags.py flags for the compatibility wrapper.
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
    args = parser.parse_args(argv)
    if args.flush_db and args.flush_tag:
        parser.error("--flush_db cannot be combined with --flush-tag")
    args.all = True
    args.rule_id = None
    return args


def legacy_reindex_args(argv=None):
    """
    Parse the old reindex_tagrule.py flags for the compatibility wrapper.
    """
    parser = argparse.ArgumentParser(
        description="Recompute Kvrocks tags from Meili documents after a tag rule change."
    )
    parser.add_argument(
        "rule_id",
        nargs="?",
        type=int,
        help="Existing Tag Rule id used to trigger the reindex.",
    )
    parser.add_argument(
        "--allrules",
        action="store_true",
        help="Reindex tags using all active Tag Rules in one pass over Meili documents.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=MAX_BATCH_SIZE,
        help=f"Documents per Meili page and Kvrocks flush (max {MAX_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--flush",
        action="store_true",
        help="Delete all existing Kvrocks tag indexes before recomputing them.",
    )
    parser.add_argument(
        "--list_tags",
        action="store_true",
        help="List distinct tag values currently indexed in Kvrocks, then exit.",
    )
    args = parser.parse_args(argv)
    if args.list_tags:
        if args.rule_id is not None or args.allrules:
            parser.error("--list_tags cannot be combined with rule_id or --allrules")
        if args.flush:
            parser.error("--list_tags cannot be combined with --flush")
        return args

    has_rule_id = args.rule_id is not None
    if has_rule_id == bool(args.allrules):
        parser.error("use either rule_id or --allrules")
    return args


def normalize_flush_tag(raw_tag):
    """
    Normalize a CLI tag value to the stored Kvrocks tag value.
    """
    tag = str(raw_tag or "").strip().lower()
    while tag.startswith("tag:") and tag.count(":") >= 2:
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
    they do not replace existing DB rows under the "newer wins" policy.
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


def get_yaml_files(args, rule_name=None):
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

    if rule_name:
        tags_file = tags_dir / f"{rule_name}.yaml"
        if not tags_file.is_file():
            raise FileNotFoundError(f"Tag YAML file not found: {tags_file}")
        return [tags_file]

    if not getattr(args, "all", True):
        return []

    return list(iter_yaml_files(tags_dir))


def should_replace(source_version, db_rule):
    """
    Return True when the YAML rule is newer than the DB row.
    """
    db_version = db_rule.updated_at or db_rule.created_at or datetime.max
    return source_version > db_version


def import_rules(args):
    """
    Import all YAML rules according to the version policy.
    """
    flush_tag = getattr(args, "flush_tag", None)

    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel

    # pylint: disable-next=import-outside-toplevel
    from app.utils.kvrocks import KVrocksIndexer
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

        rule_name = None
        rule_id = getattr(args, "rule_id", None)
        if rule_id is not None:
            selected_rule = (
                db.session.query(TagRules).filter(TagRules.id == rule_id).one_or_none()
            )
            if selected_rule is None:
                raise SystemExit(f"Tag rule id {rule_id} not found")
            rule_name = selected_rule.name

        yaml_files = get_yaml_files(args, rule_name=rule_name)
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
                        f"id={existing.id} "
                        f"yaml_version={version_label} "
                        f"db_updated_at={existing.updated_at}"
                    )
                continue

            summary["updated"] += 1
            if not args.quiet:
                print(
                    f"UPDATE {name} "
                    f"id={existing.id} "
                    f"yaml_version={version_label} "
                    f"db_updated_at={existing.updated_at}"
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


def suppress_connection_debug_logs():
    """
    Keep noisy HTTP/TCP client debug logs out of CLI output.
    """
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def load_tools_config():
    """
    Load the shared tools YAML configuration.
    """
    with open(TOOLS_CONFIG, "r", encoding="utf-8") as config_handle:
        return yaml.safe_load(config_handle) or {}


def load_reindex_runtime():
    """
    Import Flask runtime dependencies lazily so CLI help stays clean.
    """
    sys.path.insert(0, str(WEBAPP_DIR))

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import (  # pylint: disable=import-outside-toplevel
        CollectedHeaders,
        TagRules,
        ensure_default_collected_headers,
    )
    from app.utils.kvrocks import (  # pylint: disable=import-outside-toplevel
        KVrocksIndexer,
    )
    from app.utils.mutils import fetch_tlds  # pylint: disable=import-outside-toplevel
    from app.utils.result_parser import (  # pylint: disable=import-outside-toplevel
        parse_json,
    )
    from app.utils.tagrules import (  # pylint: disable=import-outside-toplevel
        compile_tag_rule_records,
    )

    return {
        "app": app,
        "db": db,
        "CollectedHeaders": CollectedHeaders,
        "TagRules": TagRules,
        "ensure_default_collected_headers": ensure_default_collected_headers,
        "KVrocksIndexer": KVrocksIndexer,
        "fetch_tlds": fetch_tlds,
        "parse_json": parse_json,
        "compile_tag_rule_records": compile_tag_rule_records,
    }


def get_tool_config_value(config, *keys):
    """
    Return the first non-empty config value matching one of the given keys.
    """
    for key in keys:
        value = config.get(key)
        if value not in (None, ""):
            return value
    return None


def configure_parser_from_tools_config(app_config, config):
    """
    Overlay parser settings from tools/config.yaml when present.
    """
    if "ONLINETLD" in config:
        app_config["ONLINETLD"] = bool(config.get("ONLINETLD"))
    if "TLDADD" in config:
        app_config["TLDADD"] = list(config.get("TLDADD") or [])
    if "TLDS" in config:
        app_config["TLDS"] = list(config.get("TLDS") or [])


def ensure_parser_tlds(app_config, fetch_tlds):
    """
    Mirror the runtime parser TLD setup for reparsing.
    """
    if "TLDS" not in app_config:
        app_config["TLDS"] = []

    if app_config.get("ONLINETLD") and not app_config.get("TLDS"):
        app_config["TLDS"] = fetch_tlds()

    extra_tlds = list(app_config.get("TLDADD", []))
    existing_tlds = set(app_config.get("TLDS", []))
    for tld in extra_tlds:
        if tld not in existing_tlds:
            app_config["TLDS"].append(tld)
            existing_tlds.add(tld)


def configure_parser_http_headers(
    app_config, db, collected_headers_model, ensure_default_headers
):
    """
    Add DB-backed HTTP header collection config to parser settings.
    """
    ensure_default_headers(db.session)
    app_config["HTTP_HEADER_COLLECTION"] = {
        str(row.header_name or "").strip().lower(): bool(row.collect_value)
        for row in db.session.query(collected_headers_model).all()
        if str(row.header_name or "").strip()
    }


def iter_meili_documents(index, page_size):
    """
    Yield Meilisearch documents page by page in read-only mode.
    """
    offset = 0
    while True:
        print(
            f"Fetching Meili documents offset={offset} limit={page_size}",
            flush=True,
        )
        documents = index.get_documents({"limit": page_size, "offset": offset})
        results = list(getattr(documents, "results", []) or [])
        if not results:
            break

        for result in results:
            yield dict(result)

        offset += len(results)


def delete_keys_by_pattern(redis_client, pattern, batch_size):
    """
    Delete keys matching one pattern without blocking on KEYS.
    """
    deleted = 0
    pending = []
    for key in redis_client.scan_iter(match=pattern, count=batch_size):
        pending.append(key)
        if len(pending) >= batch_size:
            deleted += redis_client.delete(*pending)
            print(
                f"Flush progress {pattern}: deleted={deleted}",
                flush=True,
            )
            pending = []

    if pending:
        deleted += redis_client.delete(*pending)
        print(
            f"Flush progress {pattern}: deleted={deleted}",
            flush=True,
        )

    return deleted


def flush_existing_tag_indexes(indexer, batch_size):
    """
    Remove all Kvrocks tag indexes before a full tag rebuild.
    """
    total_deleted = 0
    for pattern in ("tag:*", "tags:*"):
        print(f"Flushing existing Kvrocks keys matching {pattern}", flush=True)
        deleted = delete_keys_by_pattern(indexer.r, pattern, batch_size)
        total_deleted += deleted
        print(
            f"Flush complete for {pattern}: deleted={deleted}",
            flush=True,
        )
    print(
        f"Flush complete: deleted={total_deleted} tag-related keys",
        flush=True,
    )
    return total_deleted


def flush_tag_batch(indexer, pending_docs):
    """
    Persist one Kvrocks tag-only batch.
    """
    if not pending_docs:
        return 0
    indexer.replace_field_values_batch(
        "tag", pending_docs, batch_size=len(pending_docs)
    )
    count = len(pending_docs)
    pending_docs.clear()
    return count


def list_kvrocks_tags(redis_client, batch_size):
    """
    Print tag values by reading Kvrocks `tag:<value>` index keys.
    """
    tags = set()
    for key in redis_client.scan_iter(match="tag:*", count=batch_size):
        tag = str(key).split(":", 1)[1].strip()
        if tag:
            tags.add(tag)

    for tag in sorted(tags):
        print(tag)
    print(f"Total tags: {len(tags)}", file=sys.stderr)
    return len(tags)


def validate_batch_size(batch_size):
    """
    Keep batch sizes in the proven operating range.
    """
    if batch_size <= 0 or batch_size > MAX_BATCH_SIZE:
        raise SystemExit(f"--batch-size must be between 1 and {MAX_BATCH_SIZE}")


def load_kvrocks_endpoint(tools_config):
    """
    Return configured output Kvrocks connection settings.
    """
    kvrocks_host = get_tool_config_value(tools_config, "OUT_KVROCKS_HOST")
    kvrocks_port = get_tool_config_value(tools_config, "OUT_KVROCKS_PORT")

    if kvrocks_host in (None, "") or kvrocks_port in (None, ""):
        raise SystemExit(
            "Missing OUT_KVROCKS_HOST/OUT_KVROCKS_PORT in tools/config.yaml"
        )
    return kvrocks_host, kvrocks_port


def reindex_tags(args):
    """
    Recompute Kvrocks tags from Meilisearch documents.
    """
    import meilisearch  # pylint: disable=import-outside-toplevel

    validate_batch_size(args.batch_size)
    suppress_connection_debug_logs()
    tools_config = load_tools_config()
    kvrocks_host, kvrocks_port = load_kvrocks_endpoint(tools_config)

    runtime = load_reindex_runtime()
    app = runtime["app"]
    db = runtime["db"]
    CollectedHeaders = runtime["CollectedHeaders"]
    TagRules = runtime["TagRules"]
    ensure_default_collected_headers = runtime["ensure_default_collected_headers"]
    KVrocksIndexer = runtime["KVrocksIndexer"]
    fetch_tlds = runtime["fetch_tlds"]
    parse_json = runtime["parse_json"]
    compile_tag_rule_records = runtime["compile_tag_rule_records"]

    with app.app_context():
        configure_parser_from_tools_config(app.config, tools_config)
        ensure_parser_tlds(app.config, fetch_tlds)
        configure_parser_http_headers(
            app.config,
            db,
            CollectedHeaders,
            ensure_default_collected_headers,
        )

        active_rules = (
            db.session.query(TagRules)
            .filter(TagRules.active == True)
            .order_by(TagRules.id.asc())
            .all()
        )
        compiled_rules = compile_tag_rule_records(active_rules)
        if args.allrules:
            target_rule = None
        else:
            target_rule = (
                db.session.query(TagRules)
                .filter(TagRules.id == args.rule_id)
                .one_or_none()
            )
            if target_rule is None:
                raise SystemExit(f"Tag rule id {args.rule_id} not found")

        meili_url = get_tool_config_value(tools_config, "IN_MEILI_URL")
        meili_api_key = get_tool_config_value(tools_config, "IN_MEILI_API_KEY")
        index_name = tools_config.get("INDEX_NAME", "plum")

        if not meili_url:
            raise SystemExit("Missing IN_MEILI_URL in tools/config.yaml")

        meili_client = meilisearch.Client(meili_url, meili_api_key)
        meili_index = meili_client.index(index_name)
        indexer = KVrocksIndexer(kvrocks_host, kvrocks_port)

        if args.allrules:
            print("Mode: all active tag rules", flush=True)
        else:
            print(
                f"Rule #{target_rule.id}: {target_rule.name} "
                f"(active={bool(target_rule.active)})",
                flush=True,
            )
        print(
            f"Loaded {len(compiled_rules)} active tag rules from "
            f"{len(active_rules)} DB rows",
            flush=True,
        )
        print(f"Reading source documents from {meili_url} / index={index_name}")
        print(f"Writing tags to Kvrocks {kvrocks_host}:{kvrocks_port}")
        print(f"Batch size: {args.batch_size} documents max")

        if args.flush:
            flush_existing_tag_indexes(indexer, args.batch_size)

        pending_docs = []
        processed_docs = 0
        updated_docs = 0
        error_docs = 0

        for meili_doc in iter_meili_documents(meili_index, args.batch_size):
            processed_docs += 1

            try:
                parsed_doc = parse_json(meili_doc, app.config, tag_rules=compiled_rules)
                pending_docs.append(
                    {
                        "uid": parsed_doc["uid"],
                        "tag": parsed_doc.get("tag", []),
                    }
                )
            except Exception as error:
                error_docs += 1
                print(
                    "[WARN] Unable to reparse Meili document "
                    f"{meili_doc.get('id', '<unknown>')}: {error}",
                    flush=True,
                )
                continue

            if len(pending_docs) >= args.batch_size:
                updated_docs += flush_tag_batch(indexer, pending_docs)
                print(
                    "Progress: "
                    f"processed={processed_docs}; updated={updated_docs}; "
                    f"errors={error_docs}",
                    flush=True,
                )

        updated_docs += flush_tag_batch(indexer, pending_docs)
        print(
            "Done. "
            f"processed={processed_docs}; updated={updated_docs}; errors={error_docs}",
            flush=True,
        )


def list_tags(args):
    """
    List indexed Kvrocks tags without loading Flask.
    """
    import redis  # pylint: disable=import-outside-toplevel

    validate_batch_size(args.batch_size)
    tools_config = load_tools_config()
    kvrocks_host, kvrocks_port = load_kvrocks_endpoint(tools_config)
    redis_client = redis.Redis(
        host=kvrocks_host,
        port=kvrocks_port,
        decode_responses=True,
        db=0,
    )
    list_kvrocks_tags(redis_client, args.batch_size)


def print_import_summary(args, summary):
    """
    Print import/flush summary in the previous CLI format.
    """
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


def run_import(args):
    """
    Run an import/flush operation and print its summary.
    """
    summary = import_rules(args)
    print_import_summary(args, summary)
    return summary


def delete_rules(args):
    """
    Delete DB-backed tag rules selected by id, YAML filename, or all.
    """
    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel

    summary = {
        "deleted": 0,
        "missing": 0,
        "selector": "",
    }

    with app.app_context():
        if args.all:
            summary["selector"] = "all"
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

        if args.rule_id is not None:
            summary["selector"] = f"id={args.rule_id}"
            rule = (
                db.session.query(TagRules)
                .filter(TagRules.id == args.rule_id)
                .one_or_none()
            )
        else:
            rule_name = Path(args.tags_file).stem
            summary["selector"] = f"name={rule_name}"
            rule = db.session.query(TagRules).filter_by(name=rule_name).one_or_none()

        if rule is None:
            summary["missing"] = 1
            if not args.quiet:
                print(f"MISS tagrule {summary['selector']}")
            db.session.rollback()
            return summary

        summary["deleted"] = 1
        if not args.quiet:
            action = "WOULD_DELETE" if args.dry_run else "DELETE"
            print(f"{action} tagrule id={rule.id} name={rule.name}")
        if not args.dry_run:
            db.session.delete(rule)
            db.session.commit()
        else:
            db.session.rollback()
    return summary


def run_delete(args):
    """
    Run a DB tag-rule delete operation and print its summary.
    """
    summary = delete_rules(args)
    print(
        "Tag delete complete: "
        f"selector={summary['selector']} "
        f"deleted={summary['deleted']} "
        f"missing={summary['missing']} "
        f"dry_run={args.dry_run}"
    )
    return summary


def run_legacy_import(argv=None):
    """
    Entrypoint for tools/import_tags.py compatibility.
    """
    return run_import(legacy_import_args(argv))


def run_legacy_reindex(argv=None):
    """
    Entrypoint for tools/reindex_tagrule.py compatibility.
    """
    args = legacy_reindex_args(argv)
    if args.list_tags:
        return list_tags(args)
    return reindex_tags(args)


def main(argv=None):
    """
    CLI entrypoint. No command means print help and do nothing.
    """
    args = parse_args(argv)
    if args is None:
        return None

    if args.command == "import":
        if not args.all and args.rule_id is None and not args.tags_file:
            print(
                "Nothing to import. Use one of:\n"
                "  tag_mgmt.py import --all\n"
                "  tag_mgmt.py import --id <tag-rule-id>\n"
                "  tag_mgmt.py import --tags-file <path>"
            )
            return None
        args.flush_db = False
        args.flush_tag = None
        return run_import(args)
    if args.command == "delete":
        if not args.all and args.rule_id is None and not args.tags_file:
            print(
                "Nothing to delete. Use one of:\n"
                "  tag_mgmt.py delete --all\n"
                "  tag_mgmt.py delete --id <tag-rule-id>\n"
                "  tag_mgmt.py delete --tags-file <path>"
            )
            return None
        return run_delete(args)
    if args.command == "flush-tag":
        args.tags_dir = str(DEFAULT_TAGS_DIR)
        args.tags_file = None
        args.flush_db = False
        args.flush_tag = args.tag
        return run_import(args)
    if args.command == "reindex":
        return reindex_tags(args)
    if args.command == "list-tags":
        return list_tags(args)

    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
