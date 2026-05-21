#!/usr/bin/env python3
"""
Split IP-scoped Meilisearch dump documents into one document per port.

The smart-hash implementation is copied from D4-project/nmap2json:
https://github.com/D4-project/nmap2json/blob/main/src/nmap2json/smarthash.py
"""

import argparse
import copy
import hashlib
import json
import re
import time
import uuid
from pathlib import Path

import redis

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "meili_dump"
DEFAULT_OUTPUT_DIR = BASE_DIR / "meili_dump_port"
DEFAULT_CONFIG_FILE = BASE_DIR / "config.yaml"

HEADERS_TOCLEAN = [
    "CF-Ray",
    "content-security-policy-report-only",
    "ETag",
    "request-id",
    "Via",
    "www-authenticate",
    "X-Amz-Cf-Id",
    "x-amz-id-2",
    "x-amz-request-id",
    "x-gitlab-meta",
    "x-iplb-instance",
    "x-iplb-request-id",
    "x-ntap-sg-trace-id",
    "x-request-id",
    "x-runtime",
]

SMART_HASH_SCRIPTS = ["http-headers", "http-security-headers"]
UNKNOWN_FAVICON_MD5_RE = re.compile(
    r"\bUnknown\s+favicon\s+MD5\s*:\s*([0-9a-fA-F]{32})\b",
    re.IGNORECASE,
)


def filter_keys(obj: dict | list, exclude_keys: list):
    """
    Recursively filter out specified keys from dictionaries and lists.
    """
    if isinstance(obj, dict):
        return {
            key: filter_keys(value, exclude_keys)
            for key, value in obj.items()
            if key not in exclude_keys
        }
    if isinstance(obj, list):
        return [filter_keys(item, exclude_keys) for item in obj]
    return obj


def headers_smart_hash(obj: dict, exclude_keys=None):
    """
    Generate sha256 of normalized host result.
    """
    exclude_keys = exclude_keys or []
    filtered = filter_keys(obj, exclude_keys)
    filtered = master_clean(filtered, SMART_HASH_SCRIPTS)
    obj_str = json.dumps(filtered)
    return hashlib.sha256(obj_str.encode("utf-8")).hexdigest()


def port_smart_hash(port: dict, exclude_keys=None):
    """
    Generate sha256 of normalized port result.
    """
    exclude_keys = exclude_keys or ["hsh256"]
    filtered = filter_keys({"ports": [port]}, exclude_keys)
    filtered = master_clean(filtered, SMART_HASH_SCRIPTS)
    obj_str = json.dumps(filtered["ports"][0])
    return hashlib.sha256(obj_str.encode("utf-8")).hexdigest()


def mask_same_length(match):
    """
    Replace non-space characters by X while keeping length.
    """
    return "".join("X" if char != " " else " " for char in match.group(0))


def mask_value(match):
    """
    Replace the second regex group with X.
    """
    value = match.group(2)
    masked = "X" * len(value)
    return f"{match.group(1)}{masked}"


def mask_cookie_value(match):
    """
    Replace cookie values.
    """
    key = match.group(1)
    suffix = match.group(3) or ""
    masked = "[REDACTED]"
    return f"{key}={masked}{suffix}"


def no_time(nt_input: str):
    """
    Remove HTTP-date values from a string.
    """
    pattern = (
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2}[- ]"
        + "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        + r"[- ]\d{4} \d{2}:\d{2}:\d{2} [A-Z]{2,4}"
    )
    return re.sub(pattern, mask_same_length, nt_input)


def no_uid(nu_input: str):
    """
    Remove UUID references from a string.
    """
    pattern = r"(?:[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12})"
    return re.sub(pattern, mask_same_length, nu_input)


def anonymise_nonce(an_input: str):
    """
    Replace CSP nonce values.
    """
    pattern = re.compile(r'nonce[-=]"?([a-zA-Z0-9_\-\+]+)')
    return pattern.sub(mask_same_length, an_input)


def anonymise_correlation_id(an_corr: str):
    """
    Replace correlation_id values.
    """
    pattern = re.compile(r'(correlation_id"[:]"([a-zA-Z0-9_\-\+]+))')
    return pattern.sub(mask_same_length, an_corr)


def anonymise_cookies(ac_input):
    """
    Anonymize cookie values.
    """
    pattern = re.compile(r"(Set-Cookie:\s*[^=]+)=([^;]+)(;[^\n]*|$)", re.IGNORECASE)
    return pattern.sub(mask_cookie_value, ac_input)


def anonymise_headers(input_text: str, headers: list):
    """
    Anonymize volatile headers and volatile header parameters.
    """
    for header in headers:
        if re.search(
            rf"^\s*{re.escape(header)}\s*:", input_text, re.IGNORECASE | re.MULTILINE
        ):
            if header.lower().startswith(
                "content-security-policy"
            ) or header.lower().startswith("www-authenticate"):
                input_text = anonymise_nonce(input_text)
                continue
            if header.lower().startswith("x-gitlab-meta"):
                input_text = anonymise_correlation_id(input_text)
                continue
        pattern = re.compile(
            rf"(^\s*{re.escape(header)}\s*:\s*)(.+)", re.IGNORECASE | re.MULTILINE
        )
        input_text = pattern.sub(mask_value, input_text)
    return input_text


def master_clean(not_dedup_nmap_result: dict, scripts: list):
    """
    Remove non-relevant volatile data before hashing.
    """
    result = not_dedup_nmap_result.copy()

    for port in result.get("ports", []):
        if port.get("scripts"):
            for item in port.get("scripts"):
                for script in scripts:
                    if item.get("id") == script:
                        to_clean = item.get("output")
                        cleaned = anonymise_headers(
                            anonymise_cookies(no_uid(no_time(to_clean))),
                            HEADERS_TOCLEAN,
                        )
                        item["output"] = cleaned
    return result


def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Convert tools/meili_dump IP-scoped documents into "
            "tools/meili_dump_port port-scoped documents."
        )
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help=f"Input Meilisearch dump directory. Default: {DEFAULT_INPUT_DIR}",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Output port-scoped dump directory. Default: {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1000,
        help="Also print progress every N input documents. Default: 1000",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=10.0,
        help="Print progress at least every N seconds. Default: 10",
    )
    parser.add_argument(
        "--no-time-from-kvrocks",
        action="store_true",
        help="Do not create .time companion files from IN_KVROCKS.",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_FILE),
        help=f"Tool config file for IN_KVROCKS settings. Default: {DEFAULT_CONFIG_FILE}",
    )
    parser.add_argument(
        "--kvrocks-host",
        default=None,
        help="Override IN_KVROCKS_HOST for .time companion lookup.",
    )
    parser.add_argument(
        "--kvrocks-port",
        type=int,
        default=None,
        help="Override IN_KVROCKS_PORT for .time companion lookup.",
    )
    return parser.parse_args()


def iter_json_files(input_dir):
    """
    Iterate dumped JSON documents before writing output.
    """
    return [path for path in sorted(input_dir.rglob("*.json")) if path.is_file()]


def iter_documents(json_file):
    """
    Yield dict documents from one JSON file.
    """
    with open(json_file, "r", encoding="utf-8") as json_handle:
        obj = json.load(json_handle)

    if isinstance(obj, dict):
        yield obj
        return

    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
        return

    raise ValueError(f"Unsupported JSON type: {type(obj)}")


def add_port_hash(port):
    """
    Return a deep-copied port object with nmap2json-compatible hsh256.
    """
    port_copy = copy.deepcopy(port)
    clean_banner_outputs(port_copy)
    normalize_unknown_favicon_outputs(port_copy)
    port_hash = port_smart_hash(port_copy, exclude_keys=["hsh256"])
    hashed_port = {}
    hash_inserted = False
    for key, value in port_copy.items():
        if key == "hsh256":
            continue
        hashed_port[key] = value
        if key == "portid":
            hashed_port["hsh256"] = port_hash
            hash_inserted = True
    if not hash_inserted:
        hashed_port["hsh256"] = port_hash
    return hashed_port


def clean_banner_outputs(port):
    """
    Remove accidental newlines inside banner NSE output strings.
    """
    for script in port.get("scripts") or []:
        if script.get("id") != "banner":
            continue
        output = script.get("output")
        if isinstance(output, str):
            script["output"] = output.replace("\n", "")


def normalize_unknown_favicon_outputs(port):
    """
    Convert legacy http-favicon unknown-MD5 output to http-mm-sha-favicon shape.
    """
    for script in port.get("scripts") or []:
        output = script.get("output")
        if not isinstance(output, str):
            continue
        match = UNKNOWN_FAVICON_MD5_RE.search(output)
        if not match:
            continue

        favicon_md5 = match.group(1).lower()
        script["id"] = "http-mm-sha-favicon"
        script["favicon_md5"] = favicon_md5
        script["output"] = f"\n favicon_md5: {favicon_md5}"


def port_document_uuid(ip, port):
    """
    Return deterministic UUID for one IP/port/hash report.
    """
    port_id = str(port.get("portid") or "").strip()
    port_hash = str(port.get("hsh256") or "").strip()
    if not ip:
        raise ValueError("missing IP address")
    if not port_id:
        raise ValueError("missing portid")
    if not port_hash:
        raise ValueError("missing port hsh256")
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ip}:{port_id}:{port_hash}"))


def build_port_document(source_doc, source_port):
    """
    Build one Meilisearch document containing exactly one port.
    """
    source_body = source_doc.get("body")
    if not isinstance(source_body, dict):
        raise ValueError("document body must be an object")

    ip = source_doc.get("ip") or source_body.get("addr")
    hashed_port = add_port_hash(source_port)
    body = copy.deepcopy(source_body)
    body["ports"] = [hashed_port]
    body["hsh256"] = hashed_port["hsh256"]

    doc = copy.deepcopy(source_doc)
    doc["id"] = port_document_uuid(ip, hashed_port)
    doc["ip"] = ip
    doc["body"] = body
    return doc


def split_document(source_doc):
    """
    Split one IP-scoped document into port-scoped documents.
    """
    body = source_doc.get("body")
    if not isinstance(body, dict):
        return []

    ports = body.get("ports") or []
    if not isinstance(ports, list):
        return []

    return [
        build_port_document(source_doc, port)
        for port in ports
        if isinstance(port, dict)
    ]


def write_document(output_dir, doc):
    """
    Write one port-scoped document using id first-character sharding.
    """
    doc_id = str(doc["id"])
    target_dir = output_dir / doc_id[0]
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / f"{doc_id}.json"
    with open(target_path, "w", encoding="utf-8") as json_handle:
        json.dump(doc, json_handle, ensure_ascii=False, indent=2)
    return target_path


def write_time_companion(json_path, seen_times):
    """
    Write first_seen/last_seen companion next to a JSON document.
    """
    time_path = json_path.with_suffix(".time")
    with open(time_path, "w", encoding="utf-8") as time_handle:
        json.dump(seen_times or {}, time_handle, ensure_ascii=False, indent=2)
    return time_path


def load_config(config_path):
    """
    Load optional tools/config.yaml.
    """
    if not config_path:
        return {}
    path = Path(config_path)
    if not path.is_file():
        return {}
    import yaml  # pylint: disable=import-outside-toplevel

    with open(path, "r", encoding="utf-8") as config_handle:
        return yaml.safe_load(config_handle) or {}


def build_kvrocks_client(args):
    """
    Return Redis-compatible client for old Kvrocks timestamps, if requested.
    """
    if args.no_time_from_kvrocks:
        return None

    config = load_config(args.config)
    host = args.kvrocks_host or config.get("IN_KVROCKS_HOST") or "localhost"
    port = args.kvrocks_port or int(config.get("IN_KVROCKS_PORT") or 6666)
    return redis.Redis(host=host, port=port, decode_responses=True, db=0)


def get_original_seen_times(kvrocks_client, source_doc):
    """
    Return old first_seen/last_seen bound to the source Meilisearch document id.
    """
    if kvrocks_client is None:
        return None

    source_id = str(source_doc.get("id") or "").strip()
    if not source_id:
        return {}

    data = kvrocks_client.hgetall(f"doc:{source_id}") or {}
    return {
        "source_id": source_id,
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
    }


def format_progress(processed, total):
    """
    Render count/max, percent, and remaining todo.
    """
    if total <= 0:
        return "0/0 (100.0%) todo=0"
    processed = min(processed, total)
    todo = max(0, total - processed)
    percent = (processed / total) * 100
    return f"{processed}/{total} ({percent:.1f}%) todo={todo}"


def main():
    """
    Convert all input dump documents.
    """
    args = parse_args()
    input_dir = Path(args.input_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not input_dir.is_dir():
        raise SystemExit(f"Input directory not found: {input_dir}")
    if output_dir == input_dir or input_dir in output_dir.parents:
        raise SystemExit("Output directory must not be inside input directory")

    output_dir.mkdir(parents=True, exist_ok=True)
    kvrocks_client = build_kvrocks_client(args)
    json_files = iter_json_files(input_dir)
    total_files = len(json_files)
    progress_every = max(1, int(args.progress_every or 1000))
    progress_interval = max(1.0, float(args.progress_interval or 10.0))
    last_progress_at = time.monotonic()

    processed_files = 0
    input_documents = 0
    output_documents = 0
    output_time_files = 0
    skipped_documents = 0
    error_count = 0

    print(
        "Starting port dump split: "
        f"files={total_files} input_dir={input_dir} output_dir={output_dir} "
        f"time_from_kvrocks={bool(kvrocks_client)}",
        flush=True,
    )

    def print_progress(force=False):
        nonlocal last_progress_at
        now = time.monotonic()
        if not force and now - last_progress_at < progress_interval:
            return
        last_progress_at = now
        print(
            "Progress: "
            f"files={format_progress(processed_files, total_files)} "
            f"input_docs={input_documents} output_docs={output_documents} "
            f"time_files={output_time_files} skipped={skipped_documents} "
            f"errors={error_count}",
            flush=True,
        )

    for json_file in json_files:
        try:
            source_docs = list(iter_documents(json_file))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            error_count += 1
            print(f"[WARN] Unable to read {json_file}: {error}", flush=True)
            processed_files += 1
            print_progress()
            continue

        for source_doc in source_docs:
            input_documents += 1
            try:
                port_docs = split_document(source_doc)
                if not port_docs:
                    skipped_documents += 1
                    continue
                seen_times = get_original_seen_times(kvrocks_client, source_doc)
                for port_doc in port_docs:
                    json_path = write_document(output_dir, port_doc)
                    if seen_times is not None:
                        write_time_companion(json_path, seen_times)
                        output_time_files += 1
                    output_documents += 1
            except (TypeError, ValueError, OSError, redis.RedisError) as error:
                error_count += 1
                print(
                    f"[WARN] Unable to split {json_file} "
                    f"doc={source_doc.get('id', '<unknown>')}: {error}",
                    flush=True,
                )

            if input_documents % progress_every == 0:
                print_progress(force=True)

        processed_files += 1
        print_progress()

    print(
        "Port dump split complete: "
        f"files={format_progress(processed_files, total_files)} "
        f"input={input_documents} output={output_documents} "
        f"time_files={output_time_files} "
        f"skipped={skipped_documents} errors={error_count} "
        f"output_dir={output_dir}",
        flush=True,
    )


if __name__ == "__main__":
    main()
