#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import warnings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = BASE_DIR / "webapp"


def parse_args():
    """
    Parse CLI arguments before importing the Flask app.
    """
    parser = argparse.ArgumentParser(
        description="Parse one Plum document and include computed tags."
    )
    parser.add_argument(
        "input",
        help="Path to the source JSON document or its filename.",
    )
    return parser.parse_args()


def resolve_input_path(raw_value):
    """
    Resolve a document path while keeping compatibility with the old layout.
    """
    candidate = Path(raw_value)
    if candidate.is_file():
        return candidate

    basename = Path(raw_value).name
    search_paths = [
        Path.cwd() / basename,
        Path.cwd() / basename[:1] / basename,
        BASE_DIR / basename,
        BASE_DIR / basename[:1] / basename,
        BASE_DIR / "tools" / "meili_dump" / basename[:1] / basename,
    ]
    for path in search_paths:
        if path.is_file():
            return path

    raise FileNotFoundError(f"Input file not found: {raw_value}")


def build_parser_config(app_config, fetch_tlds):
    """
    Rebuild the parser config used by the application.
    """
    parser_config = {
        "ONLINETLD": bool(app_config.get("ONLINETLD", False)),
        "TLDS": list(app_config.get("TLDS", []) or []),
        "TLDADD": list(app_config.get("TLDADD", []) or []),
    }

    if parser_config["ONLINETLD"] and not parser_config["TLDS"]:
        parser_config["TLDS"] = fetch_tlds()

    existing_tlds = set(parser_config["TLDS"])
    for tld in parser_config["TLDADD"]:
        candidate = str(tld).strip().lower()
        if not candidate or candidate in existing_tlds:
            continue
        existing_tlds.add(candidate)
        parser_config["TLDS"].append(candidate)

    return parser_config


def main():
    """
    Load the app, active tag rules, and print the parsed JSON only.
    """
    args = parse_args()
    input_path = resolve_input_path(args.input)

    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)

    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import TagRules  # pylint: disable=import-outside-toplevel
    from app.utils.mutils import fetch_tlds  # pylint: disable=import-outside-toplevel
    from app.utils.result_parser import parse_json  # pylint: disable=import-outside-toplevel
    from app.utils.tagrules import (  # pylint: disable=import-outside-toplevel
        compile_tag_rule_records,
    )

    with app.app_context():
        parser_config = build_parser_config(app.config, fetch_tlds)
        compiled_rules = []

        try:
            active_rules = (
                db.session.query(TagRules)
                .filter(TagRules.active == True)
                .order_by(TagRules.id.asc())
                .all()
            )
            compiled_rules = compile_tag_rule_records(active_rules)
        except Exception as error:  # pragma: no cover - debug helper fallback
            print(
                f"[WARN] Unable to load active tag rules: {error}",
                file=sys.stderr,
            )

        with open(input_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)

        parsed = parse_json(document, parser_config, tag_rules=compiled_rules)
        json.dump(parsed, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
