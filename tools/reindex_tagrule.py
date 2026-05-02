#!/usr/bin/env python3
"""
Recompute Kvrocks document tags from Meilisearch documents.

The provided rule id is used as the operator trigger and validation target.
For consistency, the script recomputes the final tag set using all active rules,
then replaces only the Kvrocks `tag:*` / `tags:{uid}` indexes.
Meilisearch is used strictly as a read-only input source.
"""

import argparse
import logging
import sys
from pathlib import Path

import meilisearch
import redis
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = BASE_DIR / "webapp"
TOOLS_CONFIG = BASE_DIR / "tools" / "config.yaml"
MAX_BATCH_SIZE = 1000
sys.path.insert(0, str(WEBAPP_DIR))


def suppress_connection_debug_logs():
    """
    Keep noisy HTTP/TCP client debug logs out of this CLI output.
    """
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def parse_args():
    """
    Parse command line arguments.
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
        help="List distinct tag keys currently indexed in Kvrocks, then exit.",
    )
    args = parser.parse_args()
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


def load_tools_config():
    """
    Load the shared tools YAML configuration.
    """
    with open(TOOLS_CONFIG, "r", encoding="utf-8") as config_handle:
        return yaml.safe_load(config_handle) or {}


def load_runtime():
    """
    Import Flask runtime dependencies lazily so CLI help stays clean.
    """
    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel
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
        "TagRules": TagRules,
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
    indexer.replace_field_values_batch("tag", pending_docs, batch_size=len(pending_docs))
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


def main():
    """
    Validate the target rule id and reindex Kvrocks tags.
    """
    args = parse_args()

    if args.batch_size <= 0 or args.batch_size > MAX_BATCH_SIZE:
        raise SystemExit(
            f"--batch-size must be between 1 and {MAX_BATCH_SIZE}"
        )

    suppress_connection_debug_logs()
    tools_config = load_tools_config()
    kvrocks_host = get_tool_config_value(tools_config, "OUT_KVROCKS_HOST")
    kvrocks_port = get_tool_config_value(tools_config, "OUT_KVROCKS_PORT")

    if kvrocks_host in (None, "") or kvrocks_port in (None, ""):
        raise SystemExit("Missing OUT_KVROCKS_HOST/OUT_KVROCKS_PORT in tools/config.yaml")

    if args.list_tags:
        redis_client = redis.Redis(
            host=kvrocks_host,
            port=kvrocks_port,
            decode_responses=True,
            db=0,
        )
        list_kvrocks_tags(redis_client, args.batch_size)
        return

    runtime = load_runtime()
    app = runtime["app"]
    db = runtime["db"]
    TagRules = runtime["TagRules"]
    KVrocksIndexer = runtime["KVrocksIndexer"]
    fetch_tlds = runtime["fetch_tlds"]
    parse_json = runtime["parse_json"]
    compile_tag_rule_records = runtime["compile_tag_rule_records"]

    with app.app_context():
        configure_parser_from_tools_config(app.config, tools_config)
        ensure_parser_tlds(app.config, fetch_tlds)

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


if __name__ == "__main__":
    main()
