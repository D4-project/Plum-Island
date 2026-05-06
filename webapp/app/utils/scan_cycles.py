"""
Helpers for scan profile cycle tracking.

The scheduler already owns queue creation and target/profile runtime state.
This module only derives cycle metadata from that state:
- current cycle row for each scan profile,
- progress counters,
- finished timestamp when every applicable target has been scanned.
"""

# pylint: disable=no-name-in-module

from sqlalchemy import and_, exists, func, text

from .. import db
from ..models import (
    Jobs,
    ScanProfileCycles,
    ScanProfiles,
    TargetScanStates,
    Targets,
    assoc_scanprofiles_targets,
)
from .timeutils import utcnow_naive

SCANPROFILE_CYCLES_RETAINED = 2


def _active_applicable_state_query(profile):
    """
    Return target/profile states that currently belong to `profile`.

    `apply_to_all` profiles count every active target. Explicit profiles count
    only active targets still present in `scanprofiles_targets_assoc`. This is
    intentional: if a target is removed from a profile mid-cycle it no longer
    blocks completion; if a target is added mid-cycle it appears here after the
    normal state sync creates its `target_scan_states` row.
    """
    query = (
        db.session.query(TargetScanStates)
        .join(Targets, TargetScanStates.target_id == Targets.id)
        .filter(
            TargetScanStates.scanprofile_id == profile.id,
            Targets.active.is_(True),
        )
    )
    if profile.apply_to_all:
        return query

    return query.filter(
        exists().where(
            and_(
                assoc_scanprofiles_targets.c.scanprofile_id == profile.id,
                assoc_scanprofiles_targets.c.target_id == TargetScanStates.target_id,
            )
        )
    )


def prune_scanprofile_cycles(scanprofile_id, keep=SCANPROFILE_CYCLES_RETAINED):
    """
    Keep only the useful cycle rows for one scan profile.

    Retention is total rows per profile:
    - keep the newest running cycle when one exists,
    - fill remaining slots with newest finished cycles,
    - if no running cycle exists, keep the two newest finished cycles.

    Jobs may reference old cycle rows, so old jobs are unlinked before deleting
    old cycles. The job still keeps its scan profile label via
    `jobs.scanprofile_name`.
    """
    keep = max(1, int(keep or SCANPROFILE_CYCLES_RETAINED))
    cycles = (
        db.session.query(ScanProfileCycles)
        .filter(ScanProfileCycles.scanprofile_id == scanprofile_id)
        .all()
    )
    if len(cycles) <= keep:
        return 0

    running_cycles = sorted(
        (cycle for cycle in cycles if cycle.status == "running"),
        key=lambda cycle: (cycle.started_at, cycle.id),
        reverse=True,
    )
    finished_cycles = sorted(
        (cycle for cycle in cycles if cycle.status == "finished"),
        key=lambda cycle: (
            cycle.finished_at or cycle.started_at,
            cycle.started_at,
            cycle.id,
        ),
        reverse=True,
    )

    kept_ids = []
    if running_cycles:
        kept_ids.append(running_cycles[0].id)
    kept_ids.extend(
        cycle.id for cycle in finished_cycles[: max(0, keep - len(kept_ids))]
    )

    # If unexpected statuses exist, only keep them when no normal cycle filled
    # the retention budget.
    if len(kept_ids) < keep:
        other_cycles = sorted(
            (cycle for cycle in cycles if cycle.status not in {"running", "finished"}),
            key=lambda cycle: (cycle.started_at, cycle.id),
            reverse=True,
        )
        kept_ids.extend(cycle.id for cycle in other_cycles[: keep - len(kept_ids)])

    profile = (
        db.session.query(ScanProfiles)
        .filter(ScanProfiles.id == scanprofile_id)
        .one_or_none()
    )
    if profile is not None:
        kept_running_cycle = next(
            (cycle for cycle in running_cycles if cycle.id in kept_ids),
            None,
        )
        latest_finished_cycle = next(
            (cycle for cycle in finished_cycles if cycle.id in kept_ids),
            None,
        )
        profile.current_cycle_id = (
            kept_running_cycle.id if kept_running_cycle is not None else None
        )
        profile.last_cycle_finished_at = (
            latest_finished_cycle.finished_at
            if latest_finished_cycle is not None
            else None
        )

    obsolete_ids = [cycle.id for cycle in cycles if cycle.id not in set(kept_ids)]
    if not obsolete_ids:
        return 0

    db.session.query(Jobs).filter(Jobs.scanprofile_cycle_id.in_(obsolete_ids)).update(
        {Jobs.scanprofile_cycle_id: None},
        synchronize_session=False,
    )
    deleted = (
        db.session.query(ScanProfileCycles)
        .filter(ScanProfileCycles.id.in_(obsolete_ids))
        .delete(synchronize_session=False)
        or 0
    )
    return deleted


def prune_all_scanprofile_cycles(keep=SCANPROFILE_CYCLES_RETAINED):
    """
    Apply cycle retention to every scan profile that has cycle history.
    """
    profile_ids = [
        row[0]
        for row in db.session.query(ScanProfileCycles.scanprofile_id).distinct().all()
    ]
    return sum(
        prune_scanprofile_cycles(profile_id, keep=keep) for profile_id in profile_ids
    )


def _unfinished_job_count(scanprofile_id):
    """
    Count unfinished jobs for the profile, regardless of cycle id.

    A cycle cannot be complete while any queued or active job for the same scan
    profile still exists. Counting all unfinished profile jobs makes migration
    from old NULL `scanprofile_cycle_id` jobs safe.
    """
    return (
        db.session.query(func.count(Jobs.id))
        .filter(
            Jobs.scanprofile_id == scanprofile_id,
            Jobs.finished.is_(False),
        )
        .scalar()
        or 0
    )


def reconcile_scanprofile_cycle(scanprofile_id, cycle=None, now=None):
    """
    Recalculate one running scan-profile cycle from persisted runtime state.

    Completion rule:
    - target belongs to cycle if it is active and currently applicable to the
      profile,
    - target is complete if its target/profile state has `working = False` and
      `last_scan >= cycle.started_at`,
    - cycle finishes only when all applicable states are complete and there are
      no unfinished jobs left for that scan profile.

    The function is idempotent and does not commit. Callers own transaction
    boundaries so scheduler ticks, API job completion, and admin deletes can
    keep their existing commit behavior.
    """
    now = now or utcnow_naive()
    if cycle is None:
        cycle = (
            db.session.query(ScanProfileCycles)
            .filter(
                ScanProfileCycles.scanprofile_id == scanprofile_id,
                ScanProfileCycles.status == "running",
            )
            .order_by(ScanProfileCycles.started_at.desc(), ScanProfileCycles.id.desc())
            .first()
        )
    if cycle is None:
        return None

    profile = (
        db.session.query(ScanProfiles)
        .filter(ScanProfiles.id == scanprofile_id)
        .one_or_none()
    )
    if profile is None:
        return None

    state_query = _active_applicable_state_query(profile)
    target_count = state_query.count()
    completed_count = (
        state_query.filter(
            TargetScanStates.working.is_(False),
            TargetScanStates.last_scan.isnot(None),
            TargetScanStates.last_scan >= cycle.started_at,
        ).count()
        if cycle.started_at is not None
        else 0
    )
    unfinished_jobs = _unfinished_job_count(scanprofile_id)

    cycle.target_count = target_count
    cycle.completed_target_count = completed_count

    if completed_count >= target_count and unfinished_jobs == 0:
        cycle.status = "finished"
        cycle.finished_at = cycle.finished_at or now
        profile.current_cycle_id = None
        profile.last_cycle_finished_at = cycle.finished_at
    else:
        cycle.status = "running"
        cycle.finished_at = None
        profile.current_cycle_id = cycle.id

    prune_scanprofile_cycles(scanprofile_id)
    return cycle


def get_or_create_running_cycle(scanprofile_id, now=None):
    """
    Return current running cycle for a profile, creating one if needed.

    The scheduler calls this only after it found due target/profile states.
    Starting the cycle before jobs are inserted gives every new job the same
    `started_at` boundary and lets completion be derived from later
    `last_scan` values.
    """
    now = now or utcnow_naive()
    cycle = (
        db.session.query(ScanProfileCycles)
        .filter(
            ScanProfileCycles.scanprofile_id == scanprofile_id,
            ScanProfileCycles.status == "running",
        )
        .order_by(ScanProfileCycles.started_at.desc(), ScanProfileCycles.id.desc())
        .first()
    )
    if cycle is None:
        cycle = ScanProfileCycles(
            scanprofile_id=scanprofile_id,
            started_at=now,
            status="running",
        )
        db.session.add(cycle)
        db.session.flush()

    return reconcile_scanprofile_cycle(scanprofile_id, cycle=cycle, now=now)


def reconcile_running_scanprofile_cycles(now=None):
    """
    Recalculate every running cycle once.

    This runs at scheduler start so cycle metadata survives process restarts
    and catches state changes from admin edits without changing scheduling
    order or batching.
    """
    now = now or utcnow_naive()
    running_cycles = (
        db.session.query(ScanProfileCycles)
        .filter(ScanProfileCycles.status == "running")
        .order_by(ScanProfileCycles.scanprofile_id.asc(), ScanProfileCycles.id.asc())
        .all()
    )
    for cycle in running_cycles:
        reconcile_scanprofile_cycle(cycle.scanprofile_id, cycle=cycle, now=now)
    return len(running_cycles)


def release_orphaned_scan_states_for_profile(scanprofile_id, target_ids=None):
    """
    Release working states for a profile after admin job deletion.

    The scheduler still has its periodic global orphan repair. This targeted
    path exists so deleting a job does not leave the profile cycle waiting for
    the next global sweep when affected targets can be known from the deleted
    job rows.
    """
    params = {"profile_id": scanprofile_id}
    target_filter = ""
    if target_ids is not None:
        target_ids = sorted({int(target_id) for target_id in target_ids})
        if not target_ids:
            return 0
        target_params = {
            f"target_id_{index}": target_id
            for index, target_id in enumerate(target_ids)
        }
        params.update(target_params)
        placeholders = ", ".join(
            f":target_id_{index}" for index in range(len(target_ids))
        )
        target_filter = f"AND tss.target_id IN ({placeholders})"

    released = (
        db.session.execute(
            text(f"""
                UPDATE target_scan_states AS tss
                   SET working = 0
                 WHERE tss.scanprofile_id = :profile_id
                   AND tss.working = 1
                   {target_filter}
                   AND NOT EXISTS (
                        SELECT 1
                          FROM jobs_targets_assoc AS jta
                          JOIN jobs AS j ON j.id = jta.job_id
                         WHERE jta.target_id = tss.target_id
                           AND j.scanprofile_id = tss.scanprofile_id
                           AND j.finished = 0
                   )
                """),
            params,
        ).rowcount
        or 0
    )

    affected_target_ids = target_ids
    if affected_target_ids is None:
        affected_target_ids = [
            row[0]
            for row in db.session.execute(
                text("""
                    SELECT target_id
                      FROM target_scan_states
                     WHERE scanprofile_id = :profile_id
                    """),
                {"profile_id": scanprofile_id},
            ).fetchall()
        ]

    for target_id in affected_target_ids:
        db.session.execute(
            text("""
                UPDATE targets
                   SET working = 0
                 WHERE id = :target_id
                   AND working = 1
                   AND NOT EXISTS (
                        SELECT 1
                          FROM target_scan_states AS tss
                         WHERE tss.target_id = targets.id
                           AND tss.working = 1
                   )
                """),
            {"target_id": target_id},
        )

    return released
