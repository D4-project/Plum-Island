#!/usr/bin/env python3
"""Scheduler child for resumable index reconciliation; not a second scheduler."""

import os
from pathlib import Path
import signal
import sys


def install_stop_handlers(worker):
    """Turn process-manager signals into a checkpointed stop request."""

    def request_stop(_signal, _frame):
        worker.stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)


def main():
    """Load controller configuration, then execute one frozen reconciliation."""
    os.environ.pop("WERKZEUG_RUN_MAIN", None)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp"))
    import meilisearch  # pylint: disable=import-outside-toplevel
    from app import app  # pylint: disable=import-outside-toplevel
    from app.utils.kvrocks import (  # pylint: disable=import-outside-toplevel
        KVrocksIndexer,
    )  # pylint: disable=import-outside-toplevel
    from app.utils.index_reconciliation import (  # pylint: disable=import-outside-toplevel
        ReconciliationWorker,
    )  # pylint: disable=import-outside-toplevel

    raw = KVrocksIndexer(
        app.config.get("KVROCKS_HOST", "localhost"),
        app.config.get("KVROCKS_PORT", 6666),
        socket_timeout=app.config.get("KVROCKS_SOCKET_TIMEOUT_SECONDS", 30),
    ).raw
    meili = meilisearch.Client(
        app.config["MEILI_DATABASE_URI"],
        app.config["MEILI_KEY"],
        timeout=app.config.get("MEILI_HTTP_TIMEOUT_SECONDS", 30),
    ).index("plum")
    worker = ReconciliationWorker(
        raw,
        meili,
        batch_size=app.config.get("TAG_RECONCILIATION_BATCH_SIZE", 25),
        pause_seconds=app.config.get("TAG_RECONCILIATION_PAUSE_SECONDS", 0.1),
    )

    install_stop_handlers(worker)
    with app.app_context():
        worker.run()


if __name__ == "__main__":
    main()
