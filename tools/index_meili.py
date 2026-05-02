#!/bin/env python
"""
Import dumped Meilisearch JSON documents into the configured OUT Meilisearch.
"""

import argparse
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "meili_dump"
DEFAULT_BATCH_SIZE = 1000


def load_config():
    """
    Load tools/config.yaml.
    """
    import yaml  # pylint: disable=import-outside-toplevel

    with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def get_config_value(config, *names, default=None):
    """
    Return the first configured value for a list of key names.
    """
    for name in names:
        value = config.get(name)
        if value not in (None, ""):
            return value
    return default


def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Import dumped JSON documents into OUT Meilisearch."
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help=f"Directory containing dumped JSON documents. Default: {DEFAULT_INPUT_DIR}",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Documents per Meilisearch batch. Default: {DEFAULT_BATCH_SIZE}",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Count total documents before importing and show percentages. "
            "This makes startup slower on large dumps."
        ),
    )
    return parser.parse_args()


def iter_json_files(input_dir):
    """
    Iterate every dumped Meilisearch JSON document.
    """
    for json_file in sorted(input_dir.rglob("*.json")):
        if json_file.is_file():
            yield json_file


def iter_documents(json_files):
    """
    Yield documents from JSON files.
    """
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as json_handle:
                obj = json.load(json_handle)
        except Exception as error:  # pylint: disable=broad-except
            yield None, f"[WARN] Unable to read {json_file}: {error}"
            continue

        if isinstance(obj, dict):
            yield obj, None
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item, None
                else:
                    yield None, f"[WARN] Unsupported item type in {json_file}: {type(item)}"
        else:
            yield None, f"[WARN] Unsupported JSON type in {json_file}: {type(obj)}"


def count_documents(json_files):
    """
    Count importable documents and unreadable/unsupported JSON entries.
    """
    total_count = 0
    error_count = 0
    for doc, error in iter_documents(json_files):
        if error:
            error_count += 1
            continue
        if doc is not None:
            total_count += 1
    return total_count, error_count


def format_progress(count, total_count):
    """
    Format count with percentage.
    """
    if total_count:
        percentage = (count / total_count) * 100
        return f"{count}/{total_count} ({percentage:.1f}%)"
    return str(count)


def flush_batch(index, batch):
    """
    Send one batch to Meilisearch.
    """
    if not batch:
        return 0
    index.add_documents(batch)
    count = len(batch)
    batch.clear()
    return count


def main():
    """
    Import dump documents into OUT Meilisearch.
    """
    args = parse_args()
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be >= 1")

    import meilisearch  # pylint: disable=import-outside-toplevel

    config = load_config()
    meili_url = get_config_value(config, "OUT_MEILI_URL")
    meili_api_key = get_config_value(config, "OUT_MEILI_API_KEY")
    index_name = get_config_value(config, "INDEX_NAME", default="plum")

    if not meili_url:
        raise SystemExit("Missing OUT_MEILI_URL in tools/config.yaml")

    input_dir = Path(args.input_dir)
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory not found: {input_dir}")

    print(f"Reading JSON dump from {input_dir}", flush=True)
    print(f"Writing documents to {meili_url} / index={index_name}", flush=True)
    print(f"Batch size: {args.batch_size}", flush=True)
    total_count = None
    if args.progress:
        print("Counting JSON documents...", flush=True)
        total_count, preflight_error_count = count_documents(iter_json_files(input_dir))
        print(
            f"Found {total_count} importable documents "
            f"({preflight_error_count} preflight errors)",
            flush=True,
        )

    client = meilisearch.Client(meili_url, meili_api_key)
    index = client.index(index_name)

    batch = []
    processed_count = 0
    indexed_count = 0
    error_count = 0

    for doc, error in iter_documents(iter_json_files(input_dir)):
        processed_count += 1
        if error:
            error_count += 1
            print(error, flush=True)
            continue

        batch.append(doc)
        if len(batch) >= args.batch_size:
            indexed_count += flush_batch(index, batch)
            print(
                f"Progress: processed={processed_count}; "
                f"indexed={format_progress(indexed_count, total_count)}; "
                f"errors={error_count}",
                flush=True,
            )

    indexed_count += flush_batch(index, batch)
    print(
        "Meilisearch import complete: "
        f"processed={processed_count} "
        f"indexed={format_progress(indexed_count, total_count)} "
        f"errors={error_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
