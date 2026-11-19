"""Controller integration for committed rule snapshots and operator status."""

from app.utils.tag_reconciliation import rule_snapshot


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
