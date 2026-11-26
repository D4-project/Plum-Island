#!/usr/bin/env python3
"""Inspect reconciliation or collect retired generations with readers offline.

Cleanup is dry-run by default. --apply --offline explicitly asserts that all
web/API/export/report readers and other controller instances have been stopped.
Ancestors of the active or unfinished generation are always retained.
"""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webapp"))
sys.path.insert(0, str(ROOT / "webapp/app/utils"))

from index_generations import (  # pylint: disable=wrong-import-position
    ACTIVE,
    CONTROL,
    GenerationClient,
    file_lock,
    read_json,
)
from index_reconciliation import (  # pylint: disable=wrong-import-position
    journal_id,
    reconciliation_status,
    state_directory,
    write_barrier,
)


def retired_keys(raw):
    """Yield only unreachable managed keys; never touch legacy/unrelated data."""
    active = raw.get(ACTIVE) or ""
    retained = set(GenerationClient(raw, active).chain())
    job = read_json(raw, "job", {})
    unfinished = job.get("id") if job.get("phase", "done") != "done" else None
    journal = journal_id(job) if unfinished else None
    if unfinished:
        retained.update(GenerationClient(raw, unfinished).chain())
    pattern = re.compile(re.escape(CONTROL) + r"g:([a-f0-9]{32}):")
    # A cursor pins a whole ancestry, not only the generation holding its lease.
    for key in raw.scan_iter(match=CONTROL + "g:*:lease:*", count=500):
        match = pattern.match(key)
        if match:
            retained.update(GenerationClient(raw, match.group(1)).chain())
    for key in raw.scan_iter(match=CONTROL + "g:*", count=500):
        match = pattern.match(key)
        if match and match.group(1) not in retained:
            yield key
    for kind in ("journal", "journal_rules", "processed", "candidates", "deleted"):
        keep = unfinished if kind in ("processed", "candidates") else journal
        for key in raw.scan_iter(match=f"{CONTROL}{kind}:*", count=500):
            if key.rsplit(":", 1)[-1] != keep:
                yield key


def main():
    """Use the controller's endpoint and refuse concurrent worker cleanup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("status", "cleanup"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if args.apply and not args.offline:
        parser.error("--apply requires --offline: stop all readers/controllers first")
    import config  # pylint: disable=import-outside-toplevel,import-error
    import redis  # pylint: disable=import-outside-toplevel
    from plum_settings import (  # pylint: disable=import-outside-toplevel
        tool_configuration,
    )

    applied = tool_configuration(config)

    raw = redis.Redis(
        host=applied["KVROCKS_HOST"],
        port=applied["KVROCKS_PORT"],
        decode_responses=True,
        socket_timeout=30,
    )
    if args.operation == "status":
        state = reconciliation_status(raw)
        # Keep this administrative path independent of Flask initialization.
        state["pacing"] = read_json(raw, "pacing", {})
        print(json.dumps(state, indent=2))
        return
    count = 0
    with file_lock(state_directory() / "worker.lock", blocking=False), write_barrier():
        batch = []
        for key in retired_keys(raw):
            count += 1
            if args.apply:
                batch.append(key)
                if len(batch) >= 500:
                    raw.unlink(*batch)
                    batch.clear()
        if batch:
            raw.unlink(*batch)
    print(f"{'Removed' if args.apply else 'Would remove'} {count} retired managed keys")


if __name__ == "__main__":
    main()
