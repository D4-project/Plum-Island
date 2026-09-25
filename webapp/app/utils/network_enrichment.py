"""Durable per-target CIRCL refreshes, with HTTP outside SQL transactions."""

from datetime import timedelta
import logging
import time
from uuid import uuid4

import requests
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app import db
from app.models import AutonomousSystems, Targets
from app.utils.ip2asn import lookup_network_information, target_type
from app.utils.timeutils import ensure_utc_naive, utcnow_naive

LOGGER = logging.getLogger(__name__)
FRESHNESS = timedelta(hours=24)


def enrichment_due(target, now=None):
    """Freshness belongs to the target lookup, not its shared AS record."""
    if target_type(target.value) == "FQDN":
        return False
    updated = ensure_utc_naive(target.network_updated_at)
    return (
        target.network_asn is None
        or updated is None
        or (now or utcnow_naive()) - updated > FRESHNESS
    )


def request_network_refresh(target, now=None):
    """Queue inside the insertion/scan transaction; no HTTP or extra commit."""
    if enrichment_due(target, now):
        target.network_refresh_pending = True


def _store_information(session, info, now):
    """Upsert one ASN, resolving competing inserts through its unique key."""
    system = session.get(AutonomousSystems, info["asn"])
    if system is None:
        try:
            with session.begin_nested():
                system = AutonomousSystems(**info, updated_at=now)
                session.add(system)
                session.flush()
        except IntegrityError:
            system = session.get(AutonomousSystems, info["asn"])
            if system is None:
                raise
    if system.updated_at is None or system.updated_at <= now:
        for name, value in info.items():
            setattr(system, name, value)
        system.updated_at = now
    return system


def refresh_target_network(target_id, force=False, session_factory=None):
    """Claim, look up, then persist; never commit the caller's session.

    A durable lease deduplicates automatic refreshes across processes. Manual
    requests ignore freshness/backoff but report an already-running lookup.
    A changed target value or superseded lease prevents stale results applying.
    """
    session_factory = session_factory or sessionmaker(bind=db.engine)
    timeout = float(db.app.config.get("NETWORK_LOOKUP_TIMEOUT_SECONDS", 10))
    now = utcnow_naive()
    token = str(uuid4())
    with session_factory() as session:
        target = session.get(Targets, target_id)
        if target is None or target_type(target.value) == "FQDN":
            return "missing" if target is None else "unavailable"
        value = target.value
        if not force and not enrichment_due(target, now):
            session.query(Targets).filter(
                Targets.id == target_id,
                Targets.value == value,
                Targets.network_updated_at == target.network_updated_at,
            ).update(
                {Targets.network_refresh_pending: False}, synchronize_session=False
            )
            session.commit()
            return "fresh"
        session.rollback()  # Release the read snapshot before acquiring a lease.
        claim = session.query(Targets).filter(
            Targets.id == target_id,
            Targets.value == value,
            or_(
                Targets.network_claim_until.is_(None), Targets.network_claim_until < now
            ),
        )
        if not force:
            claim = claim.filter(
                or_(
                    Targets.network_retry_at.is_(None), Targets.network_retry_at <= now
                ),
                or_(
                    Targets.network_updated_at.is_(None),
                    Targets.network_asn.is_(None),
                    Targets.network_updated_at < now - FRESHNESS,
                ),
            )
        claimed = claim.update(
            {
                Targets.network_claim: token,
                Targets.network_claim_until: now + timedelta(seconds=timeout * 3),
            },
            synchronize_session=False,
        )
        session.commit()
        if not claimed:
            return "busy"

        try:
            info = lookup_network_information(value, timeout=timeout)
        except (requests.RequestException, ValueError, TypeError) as error:
            LOGGER.warning(
                "Network enrichment failed for target %s: %s", target_id, error
            )
            session.query(Targets).filter(
                Targets.id == target_id,
                Targets.network_claim == token,
            ).update(
                {
                    Targets.network_claim: None,
                    Targets.network_claim_until: None,
                    Targets.network_refresh_pending: True,
                    Targets.network_retry_at: utcnow_naive()
                    + timedelta(
                        minutes=float(db.app.config.get("SCHEDULER_DELAY", 10))
                    ),
                },
                synchronize_session=False,
            )
            session.commit()
            return "failed"

        completed_at = utcnow_naive()
        # Conditional write locks this target before updating shared AS data.
        retained = (
            session.query(Targets)
            .filter(
                Targets.id == target_id,
                Targets.value == value,
                Targets.network_claim == token,
            )
            .update(
                {Targets.network_updated_at: completed_at}, synchronize_session=False
            )
        )
        if not retained:
            session.rollback()
            return "superseded"
        _store_information(session, info, completed_at)
        session.flush()
        session.query(Targets).filter(Targets.id == target_id).update(
            {
                Targets.network_asn: info["asn"],
                Targets.network_refresh_pending: False,
                Targets.network_retry_at: None,
                Targets.network_claim: None,
                Targets.network_claim_until: None,
            },
            synchronize_session=False,
        )
        session.commit()
        return "updated"


def process_pending_network_refreshes():
    """Bound automatic work in its own scheduler slot, independently of scans."""
    factory = sessionmaker(bind=db.engine)
    now = utcnow_naive()
    limit = int(db.app.config.get("NETWORK_REFRESH_BATCH_SIZE", 32))
    budget = float(db.app.config.get("SCHEDULER_QUEUE_TIME_BUDGET_SECONDS", 45))
    with factory() as session:
        ids = [
            row[0]
            for row in session.query(Targets.id)
            .filter(
                Targets.network_refresh_pending.is_(True),
                or_(
                    Targets.network_retry_at.is_(None), Targets.network_retry_at <= now
                ),
                or_(
                    Targets.network_claim_until.is_(None),
                    Targets.network_claim_until < now,
                ),
            )
            .order_by(Targets.id)
            .limit(limit)
        ]
    started = time.monotonic()
    for target_id in ids:
        if time.monotonic() - started >= budget:
            break
        try:
            refresh_target_network(target_id, session_factory=factory)
        except SQLAlchemyError:
            LOGGER.exception(
                "Could not persist network enrichment for target %s", target_id
            )
