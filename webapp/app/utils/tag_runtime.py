"""Controller integration for committed rule snapshots and operator status."""

import logging

from redis.exceptions import RedisError

from app.utils.index_generations import file_lock
from app.utils.index_reconciliation import queue_snapshot, state_directory
from app.utils.kvrocks import KVrocksIndexer
from app.utils.tag_reconciliation import rule_snapshot

logger = logging.getLogger(__name__)


def desired_snapshot():
    """Read committed configuration using the caller's application context."""
    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import (  # pylint: disable=import-outside-toplevel
        CollectedHeaders,
        TagRules,
    )

    return rule_snapshot(
        db.session.query(TagRules).order_by(TagRules.uuid).all(),
        app.config,
        db.session.query(CollectedHeaders).order_by(CollectedHeaders.header_name).all(),
    )


def queue_committed_snapshot(raw, full=False):
    """Order SQL reads and submissions so a stale scheduler tick cannot win."""
    from app import app  # pylint: disable=import-outside-toplevel

    with file_lock(state_directory() / "rules_snapshot.lock"), app.app_context():
        snapshot = desired_snapshot()
        queue_snapshot(raw, snapshot, full=full)
        return snapshot


def notify_rule_change():
    """Notify a running worker after commit; scheduler polling covers outages."""
    from app import app  # pylint: disable=import-outside-toplevel

    raw = KVrocksIndexer(
        app.config["KVROCKS_HOST"], app.config["KVROCKS_PORT"], socket_timeout=1
    ).raw
    try:
        queue_committed_snapshot(raw)
    except (RedisError, OSError):
        logger.warning("Rule snapshot submission deferred to the index scheduler")
