"""
This module manage asynchrone tasks
"""

import os
import atexit
import logging
import shutil
import uuid
import json
import time
import copy
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import SchedulerNotRunningError
from netaddr import IPNetwork, cidr_merge
import meilisearch
from meilisearch.errors import MeilisearchError
from nmap2json.smarthash import port_smart_hash
from requests.exceptions import HTTPError
from sqlalchemy import text
from sqlalchemy.orm import joinedload
from . import db
from .models import Jobs, ScanProfiles, TargetScanStates, assoc_jobs_targets
from .models import Reports
from .models import (
    CollectedHeaders,
    ensure_default_collected_headers,
    ensure_rule_required_headers,
)
from .models import TagRules
from .utils.mutils import compute_scan_unit_count_list, is_valid_fqdn, fetch_tlds
from .utils.kvrocks import KVrocksIndexer
from .utils.result_parser import parse_json
from .utils.reports import (
    build_report_markdown,
    compute_new_open_ports,
    collect_report_ports,
    collect_report_passive_dns_fqdns,
    collect_report_requested_fqdns,
    collect_report_tags,
    compute_next_report_run,
    compute_report_interval,
    compute_previous_report_interval,
    datetime_to_epoch,
    send_report_markdown,
)
from .utils.tagrules import compile_tag_rule_records
from .utils.timeutils import utcnow_aware, utcnow_naive
from .utils.scan_cycles import (
    get_current_max_target_id,
    get_or_create_running_cycle,
    get_running_scanprofile_cycle,
    reconcile_scanprofile_cycle,
)

logger = logging.getLogger("flask_appbuilder")

JOB_TARGET_CHUNK_SIZE = 256
DEFAULT_QUEUE_TARGET_JOBS_PER_PROFILE = 256
DEFAULT_QUEUE_STATE_BATCH_SIZE = JOB_TARGET_CHUNK_SIZE
DEFAULT_STATE_SYNC_BATCH_SIZE = 2048
DEFAULT_MAX_NEW_JOBS_PER_TICK = 1024
DEFAULT_QUEUE_TIME_BUDGET_SECONDS = 45
QUEUE_GENERATION_STALL_SECONDS = 300
QUEUE_GENERATION_ZERO_LOG_INTERVAL_SECONDS = 300
DEFAULT_ORPHAN_SWEEP_INTERVAL_SECONDS = 900
DEFAULT_ORPHAN_SWEEP_BATCH_SIZE = 2000
DEFAULT_PRIORITY_RETAG_BATCH_SIZE = 1000
STALLED_JOB_TIMEOUT = timedelta(hours=2)
DEFAULT_MEILI_HTTP_TIMEOUT_SECONDS = 10
DEFAULT_KVROCKS_SOCKET_TIMEOUT_SECONDS = 10
MEILI_EXPORT_BATCH_SIZE = 2500
UNKNOWN_FAVICON_MD5_RE = re.compile(
    r"\bUnknown\s+favicon\s+MD5\s*:\s*([0-9a-fA-F]{32})\b",
    re.IGNORECASE,
)

_queue_generation_lock = threading.Lock()
_queue_generation_progress = {
    "active": False,
    "stage": "idle",
    "tick_started_at": None,
    "stage_started_at": None,
    "last_job_commit_at": None,
    "zero_generation_since": None,
    "zero_generation_ticks": 0,
    "last_zero_alert_at": None,
    "last_summary": {},
}


class MeiliExportTaskError(RuntimeError):
    """Raised when Meilisearch rejects an asynchronous export task."""


@dataclass(frozen=True)
class ExportContext:
    """Immutable dependencies used during one scheduler export transition."""

    meili_idx: object
    kvrocks_idx: object
    input_dir: str
    parser_config: dict
    active_tag_rules: list


def _get_meili_task_uid(queued_task):
    """Extract a task UID from supported Meilisearch SDK response variants."""
    task_uid = getattr(queued_task, "task_uid", None)
    if task_uid is None:
        task_uid = getattr(queued_task, "uid", None)
    if task_uid is None:
        raise MeiliExportTaskError(
            "Meilisearch add_documents returned no task identifier"
        )
    return int(task_uid)


def _clean_banner_outputs(port):
    """
    Remove accidental newlines inside banner NSE output strings.
    """
    for script in port.get("scripts") or []:
        if script.get("id") != "banner":
            continue
        output = script.get("output")
        if isinstance(output, str):
            script["output"] = output.replace("\n", "")


def _normalize_unknown_favicon_outputs(port):
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


def _add_port_hash(port):
    """
    Return a deep-copied port object with computed hsh256.
    """
    port_copy = copy.deepcopy(port)
    _clean_banner_outputs(port_copy)
    _normalize_unknown_favicon_outputs(port_copy)
    port_hash = port_smart_hash(port_copy)
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


def _strip_port_hash(port):
    """
    Return a port copy without the internal hsh256 helper field.
    """
    public_port = copy.deepcopy(port)
    public_port.pop("hsh256", None)
    return public_port


def _port_document_uuid(ip, port):
    """
    Return deterministic UUID for one IP/port/hash report.
    """
    port_id = str(port.get("portid") or "").strip()
    port_hash = str(port.get("hsh256") or "").strip()
    if not ip or not port_id or not port_hash:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ip}:{port_id}:{port_hash}"))


def _split_scan_result_by_port(scan_result):
    """
    Build one Meilisearch document per port from one scanner result.
    """
    if not isinstance(scan_result, dict):
        return []

    ip = scan_result.get("addr")
    ports = scan_result.get("ports") or []
    if not ip or not isinstance(ports, list):
        return []

    port_documents = []
    for port in ports:
        if not isinstance(port, dict):
            continue
        hashed_port = _add_port_hash(port)
        doc_id = _port_document_uuid(ip, hashed_port)
        if not doc_id:
            continue

        port_hash = hashed_port["hsh256"]
        body = copy.deepcopy(scan_result)
        body["ports"] = [_strip_port_hash(hashed_port)]
        body["hsh256"] = port_hash
        port_documents.append(
            {
                "id": doc_id,
                "ip": ip,
                "body": body,
            }
        )
    return port_documents


def _begin_queue_generation():
    """Publish the start of a queue-generation tick for the watchdog."""
    now = time.perf_counter()
    with _queue_generation_lock:
        _queue_generation_progress.update(
            {
                "active": True,
                "stage": "starting",
                "tick_started_at": now,
                "stage_started_at": now,
                "last_job_commit_at": now,
                "profile": None,
                "profile_index": None,
                "profile_total": None,
                "cycle_id": None,
                "max_target_id": None,
                "batch": None,
                "phase": None,
                "limit": None,
                "due_states": None,
                "queue_waiting": None,
                "queue_target": None,
                "jobs_created_tick": 0,
            }
        )


def _mark_queue_generation_stage(stage, **details):
    """Update in-memory queue progress without touching the application DB."""
    now = time.perf_counter()
    with _queue_generation_lock:
        if not _queue_generation_progress["active"]:
            return
        _queue_generation_progress["stage"] = stage
        _queue_generation_progress["stage_started_at"] = now
        _queue_generation_progress.update(details)


def _record_queue_generation_commit(jobs_created, **details):
    """Record a committed batch so watchdog alerts measure real output."""
    now = time.perf_counter()
    with _queue_generation_lock:
        if not _queue_generation_progress["active"]:
            return
        _queue_generation_progress["stage"] = "batch_committed"
        _queue_generation_progress["stage_started_at"] = now
        _queue_generation_progress.update(details)
        _queue_generation_progress["jobs_created_tick"] = int(
            _queue_generation_progress.get("jobs_created_tick") or 0
        ) + int(jobs_created or 0)
        if jobs_created:
            _queue_generation_progress["last_job_commit_at"] = now


def _finish_queue_generation(summary=None, error=None):
    """Close watchdog telemetry and track consecutive zero-output ticks."""
    now = time.perf_counter()
    summary = summary if isinstance(summary, dict) else {}
    jobs_created = int(summary.get("jobs_created", 0) or 0)
    with _queue_generation_lock:
        _queue_generation_progress["active"] = False
        _queue_generation_progress["stage"] = "failed" if error else "finished"
        _queue_generation_progress["stage_started_at"] = now
        _queue_generation_progress["last_finished_at"] = now
        _queue_generation_progress["last_error"] = error
        _queue_generation_progress["last_summary"] = dict(summary)
        if jobs_created > 0:
            _queue_generation_progress["zero_generation_since"] = None
            _queue_generation_progress["zero_generation_ticks"] = 0
            _queue_generation_progress["last_zero_alert_at"] = None
        else:
            if _queue_generation_progress["zero_generation_since"] is None:
                _queue_generation_progress["zero_generation_since"] = now
                _queue_generation_progress["last_zero_alert_at"] = None
            _queue_generation_progress["zero_generation_ticks"] += 1


def _run_queue_generation_step():
    """Run job creation while guaranteeing watchdog state is finalized."""
    _begin_queue_generation()
    try:
        summary = task_create_jobs()
    except Exception as exc:
        _finish_queue_generation(error=f"{type(exc).__name__}: {exc}")
        raise
    _finish_queue_generation(summary=summary)
    return summary


def _log_queue_generation_watchdog(now=None):
    """Report a running stall or five minutes of completed zero-output ticks."""
    now = time.perf_counter() if now is None else now
    with _queue_generation_lock:
        progress = dict(_queue_generation_progress)

        if progress["active"]:
            tick_age = now - progress["tick_started_at"]
            stage_age = now - progress["stage_started_at"]
            no_commit_age = now - progress["last_job_commit_at"]
            stalled = no_commit_age >= QUEUE_GENERATION_STALL_SECONDS
        else:
            zero_since = progress.get("zero_generation_since")
            zero_age = now - zero_since if zero_since is not None else 0
            last_zero_alert = progress.get("last_zero_alert_at")
            zero_alert = (
                zero_since is not None and zero_age >= QUEUE_GENERATION_STALL_SECONDS
            )
            should_zero_alert = zero_alert and (
                last_zero_alert is None
                or now - last_zero_alert >= QUEUE_GENERATION_ZERO_LOG_INTERVAL_SECONDS
            )
            if should_zero_alert:
                _queue_generation_progress["last_zero_alert_at"] = now

    if progress["active"]:
        log_method = logger.error if stalled else logger.info
        log_method(
            "QUEUE GENERATION WATCHDOG: active=true stalled=%s tick_age=%.0fs "
            "no_job_commit=%.0fs stage=%s stage_age=%.0fs profile=%s "
            "profile_index=%s/%s cycle_id=%s max_target_id=%s batch=%s "
            "phase=%s limit=%s due_states=%s queue=%s/%s tick_jobs=%s",
            stalled,
            tick_age,
            no_commit_age,
            progress.get("stage"),
            stage_age,
            progress.get("profile"),
            progress.get("profile_index"),
            progress.get("profile_total"),
            progress.get("cycle_id"),
            progress.get("max_target_id"),
            progress.get("batch"),
            progress.get("phase"),
            progress.get("limit"),
            progress.get("due_states"),
            progress.get("queue_waiting"),
            progress.get("queue_target"),
            progress.get("jobs_created_tick"),
        )
        return {
            "active": True,
            "stalled": stalled,
            "stage": progress.get("stage"),
            "no_job_commit_seconds": int(no_commit_age),
        }

    if should_zero_alert:
        logger.warning(
            "QUEUE GENERATION WATCHDOG: no jobs generated for %.0fs across %s "
            "completed scheduler ticks; last_summary=(%s); last_error=%s",
            zero_age,
            progress.get("zero_generation_ticks"),
            _format_scheduler_summary(progress.get("last_summary")),
            progress.get("last_error"),
        )
    return {
        "active": False,
        "zero_output_seconds": int(zero_age),
        "zero_output_ticks": progress.get("zero_generation_ticks", 0),
    }


def _run_scheduler_step(step_label, step_func):
    """
    Log start/end timing for one scheduler step.
    """
    started_at = time.perf_counter()
    logger.info("Scheduler TASK: starting %s", step_label)
    summary = step_func()
    elapsed = time.perf_counter() - started_at
    summary_text = _format_scheduler_summary(summary)
    if summary_text:
        logger.info(
            "Scheduler TASK: finished %s in %.2fs (%s)",
            step_label,
            elapsed,
            summary_text,
        )
    else:
        logger.info("Scheduler TASK: finished %s in %.2fs", step_label, elapsed)
    return {"elapsed": elapsed, "summary": summary or {}}


def _format_scheduler_summary(summary):
    """
    Format compact scheduler task counters for the generic finished log line.
    """
    if not summary:
        return ""
    if isinstance(summary, str):
        return summary
    if isinstance(summary, dict):
        return ", ".join(f"{key}={value}" for key, value in summary.items())
    return str(summary)


def task_release_stalled_jobs(now=None):
    """
    Requeue unfinished jobs whose agent claim exceeded the fixed two-hour
    timeout.

    The conditional update is the ownership guard: a job claimed or finished
    after the query snapshot is not reset by this watchdog.
    """
    now = now or utcnow_naive()
    cutoff = now - STALLED_JOB_TIMEOUT
    released_jobs = (
        db.session.query(Jobs)
        .filter(
            Jobs.active == True,
            Jobs.finished == False,
            Jobs.job_start.isnot(None),
            Jobs.job_start <= cutoff,
        )
        .update(
            {
                Jobs.active: False,
                Jobs.bot_id: None,
                Jobs.job_start: None,
            },
            synchronize_session=False,
        )
        or 0
    )
    if released_jobs:
        db.session.commit()
        logger.warning(
            "Scheduler watchdog requeued %s stalled job(s) older than %s",
            released_jobs,
            cutoff.isoformat(),
        )
    return {"stalled_jobs_released": released_jobs}


def task_master_of_puppets():
    """
    Run scan orchestration independently from external-backend maintenance.
    """
    # External migration scripts and manual SQL maintenance can modify the
    # sqlite database outside this process. Start each tick from a fresh ORM
    # session so scheduler decisions use the current persisted state.
    scheduler_started_at = time.perf_counter()
    logger.info("Scheduler TASK: tick start")
    db.session.remove()
    try:
        step_durations = {
            "release_stalled_jobs": _run_scheduler_step(
                "release_stalled_jobs", task_release_stalled_jobs
            ),
            "create_jobs": _run_scheduler_step(
                "create_jobs", _run_queue_generation_step
            ),
            "profile_sync": _run_scheduler_step(
                "profile_sync", task_sync_queued_profile_jobs
            ),
        }
        total_elapsed = time.perf_counter() - scheduler_started_at
        logger.info(
            "Scheduler TASK: tick complete in %.2fs "
            "(release_stalled_jobs=%.2fs, create_jobs=%.2fs, profile_sync=%.2fs)",
            total_elapsed,
            step_durations["release_stalled_jobs"]["elapsed"],
            step_durations["create_jobs"]["elapsed"],
            step_durations["profile_sync"]["elapsed"],
        )
    finally:
        db.session.remove()


def task_scheduler_maintenance():
    """Run result export and housekeeping without blocking scan orchestration."""
    maintenance_started_at = time.perf_counter()
    logger.info("Scheduler MAINTENANCE: tick start")
    _log_queue_generation_watchdog()
    db.session.remove()
    try:
        step_durations = {
            "export_to_dbs": _run_scheduler_step("export_to_dbs", task_export_to_dbs),
            "reports": _run_scheduler_step("reports", task_run_due_reports),
            "cleanup_jobs": _run_scheduler_step("cleanup_jobs", task_cleanup_jobs),
            "cleanup_search_sessions": _run_scheduler_step(
                "cleanup_search_sessions", task_cleanup_search_sessions
            ),
            "cleanup_export_jobs": _run_scheduler_step(
                "cleanup_export_jobs", task_cleanup_export_jobs
            ),
        }
        total_elapsed = time.perf_counter() - maintenance_started_at
        logger.info(
            "Scheduler MAINTENANCE: tick complete in %.2fs "
            "(export_to_dbs=%.2fs, reports=%.2fs, cleanup_jobs=%.2fs, "
            "cleanup_search_sessions=%.2fs, cleanup_export_jobs=%.2fs)",
            total_elapsed,
            step_durations["export_to_dbs"]["elapsed"],
            step_durations["reports"]["elapsed"],
            step_durations["cleanup_jobs"]["elapsed"],
            step_durations["cleanup_search_sessions"]["elapsed"],
            step_durations["cleanup_export_jobs"]["elapsed"],
        )
    finally:
        db.session.remove()


def check_json_storage(json_folder):
    """
    Will create json storages subfolder
    and migrate existing json to the subfolder accordly.
    """
    for folder in "1234567890abcdef":
        os.makedirs(os.path.join(json_folder, folder), exist_ok=True)

    # Smart migration from json to subfolders if needed.
    for filename in os.listdir(json_folder):
        if filename.endswith(".json"):
            logger.debug("Moving %s to sub json foler", filename)
            shutil.move(
                os.path.join(json_folder, filename),
                os.path.join(json_folder, filename[0], filename),
            )


def _serialize_profile_ports(profile):
    """
    Convert a profile port selection to a stable csv list for Nmap.
    """
    values = sorted({port.value for port in profile.ports})
    return ",".join(str(port) for port in values)


def _serialize_profile_nses(profile):
    """
    Convert a profile NSE selection to a stable csv list.
    """
    values = sorted({nse.name for nse in profile.nses})
    return ",".join(values)


def _get_scheduler_int_config(name, default_value, minimum=1):
    """
    Read an integer scheduler setting with a minimum guardrail.
    """
    try:
        value = int(db.app.config.get(name, default_value))
    except (TypeError, ValueError):
        value = default_value
    return max(value, minimum)


def _queue_time_budget_reached(deadline, completed_work_units):
    """
    Stop between state batches after at least one bounded unit was attempted.

    The first queue load is always allowed, even when maintenance consumed the
    nominal budget, so a tick still has an opportunity to create useful work.

    A single target is deliberately atomic. In particular, a /16 may consume
    slightly more than the configured time or job budget so all of its /24
    jobs are queued together and the target is never only partially covered.
    """
    return completed_work_units > 0 and time.perf_counter() >= deadline


def _release_orphaned_working_states():
    """
    Release a bounded batch of target/profile states stuck in working mode
    without unfinished jobs.
    """
    batch_size = _get_scheduler_int_config(
        "SCHEDULER_ORPHAN_SWEEP_BATCH_SIZE",
        DEFAULT_ORPHAN_SWEEP_BATCH_SIZE,
    )
    cursor_id = int(db.app.config.get("scheduler_orphan_sweep_cursor_id", 0) or 0)
    candidate_rows = db.session.execute(
        text("""
            SELECT id, target_id
              FROM target_scan_states
             WHERE working = 1
               AND id > :cursor_id
             ORDER BY id ASC
             LIMIT :batch_size
            """),
        {"cursor_id": cursor_id, "batch_size": batch_size},
    ).fetchall()

    if not candidate_rows:
        if cursor_id:
            db.app.config["scheduler_orphan_sweep_cursor_id"] = 0
        return {"released_states": 0, "checked_states": 0}

    db.app.config["scheduler_orphan_sweep_cursor_id"] = candidate_rows[-1][0]
    state_ids = [int(row[0]) for row in candidate_rows]
    placeholders = ", ".join(f":state_id_{index}" for index in range(len(state_ids)))
    params = {
        "batch_size": batch_size,
        **{f"state_id_{index}": state_id for index, state_id in enumerate(state_ids)},
    }
    orphan_rows = db.session.execute(
        text(f"""
            SELECT id, target_id
              FROM target_scan_states AS tss
             WHERE id IN ({placeholders})
               AND NOT EXISTS (
                    SELECT 1
                      FROM jobs_targets_assoc AS jta
                      JOIN jobs AS j ON j.id = jta.job_id
                     WHERE jta.target_id = tss.target_id
                       AND j.scanprofile_id = tss.scanprofile_id
                       AND j.finished = 0
               )
             ORDER BY id ASC
            """),
        params,
    ).fetchall()

    if not orphan_rows:
        return {"released_states": 0, "checked_states": len(candidate_rows)}

    orphan_state_ids = [row[0] for row in orphan_rows]
    target_ids = sorted({row[1] for row in orphan_rows})
    released_states = (
        db.session.query(TargetScanStates)
        .filter(TargetScanStates.id.in_(orphan_state_ids))
        .update({TargetScanStates.working: False}, synchronize_session=False)
        or 0
    )

    for target_id in target_ids:
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
    db.session.commit()
    return {
        "released_states": released_states,
        "checked_states": len(candidate_rows),
    }


def _should_run_orphan_state_release():
    """
    Run the expensive orphan sweep only periodically.
    """
    now_ts = time.time()
    interval_seconds = _get_scheduler_int_config(
        "SCHEDULER_ORPHAN_SWEEP_INTERVAL_SECONDS",
        DEFAULT_ORPHAN_SWEEP_INTERVAL_SECONDS,
        minimum=60,
    )
    last_run_ts = db.app.config.get("scheduler_last_orphan_state_release_ts", 0)
    if now_ts - last_run_ts < interval_seconds:
        return False
    db.app.config["scheduler_last_orphan_state_release_ts"] = now_ts
    return True


def _sync_missing_scan_states(deadline=None):
    """
    Seed missing target/profile runtime rows without holding a writer lock
    while searching the target set.

    Missing pairs are discovered with read-only SELECT statements. Only the
    bounded rows actually found are then inserted and committed. This matters
    on SQLite: an INSERT ... SELECT can reserve the single writer while its
    SELECT side scans every target, blocking scan-result reception even when
    it ultimately inserts zero rows.
    """
    batch_limit = _get_scheduler_int_config(
        "SCHEDULER_STATE_SYNC_BATCH_SIZE",
        DEFAULT_STATE_SYNC_BATCH_SIZE,
    )
    inserted_states = 0

    explicit_rows = db.session.execute(
        text("""
                SELECT spta.target_id, spta.scanprofile_id
                  FROM scanprofiles_targets_assoc AS spta
                  JOIN targets AS t
                    ON t.id = spta.target_id
                 WHERE t.active = 1
                   AND NOT EXISTS (
                        SELECT 1
                          FROM target_scan_states AS tss
                         WHERE tss.target_id = spta.target_id
                           AND tss.scanprofile_id = spta.scanprofile_id
                   )
                 ORDER BY spta.scanprofile_id ASC, spta.target_id ASC
                 LIMIT :limit
                """),
        {"limit": batch_limit},
    ).fetchall()
    # End the potentially long read before attempting any write. INSERT OR
    # IGNORE below makes a concurrent state creation harmless.
    db.session.commit()
    explicit_inserted = 0
    if explicit_rows:
        explicit_inserted = (
            db.session.execute(
                text("""
                    INSERT OR IGNORE INTO target_scan_states
                        (target_id, scanprofile_id, working)
                    VALUES (:target_id, :scanprofile_id, 0)
                    """),
                [
                    {"target_id": row[0], "scanprofile_id": row[1]}
                    for row in explicit_rows
                ],
            ).rowcount
            or 0
        )
        db.session.commit()
    inserted_states += explicit_inserted
    remaining = batch_limit - explicit_inserted

    if remaining > 0:
        apply_all_profiles = (
            db.session.query(ScanProfiles.id)
            .filter(ScanProfiles.apply_to_all == True)
            .order_by(ScanProfiles.priority.desc(), ScanProfiles.id.asc())
            .all()
        )
        db.session.commit()
        for row in apply_all_profiles:
            if deadline is not None and time.perf_counter() >= deadline:
                break
            profile_id = row[0]
            if remaining <= 0:
                break
            missing_rows = db.session.execute(
                text("""
                        SELECT t.id
                          FROM targets AS t
                         WHERE t.active = 1
                           AND NOT EXISTS (
                                SELECT 1
                                  FROM target_scan_states AS tss
                                 WHERE tss.target_id = t.id
                                   AND tss.scanprofile_id = :profile_id
                           )
                         ORDER BY t.id ASC
                         LIMIT :limit
                        """),
                {"profile_id": profile_id, "limit": remaining},
            ).fetchall()
            db.session.commit()
            created_for_profile = 0
            if missing_rows:
                created_for_profile = (
                    db.session.execute(
                        text("""
                            INSERT OR IGNORE INTO target_scan_states
                                (target_id, scanprofile_id, working)
                            VALUES (:target_id, :profile_id, 0)
                            """),
                        [
                            {"target_id": missing_row[0], "profile_id": profile_id}
                            for missing_row in missing_rows
                        ],
                    ).rowcount
                    or 0
                )
                db.session.commit()
            inserted_states += created_for_profile
            remaining -= created_for_profile

    return inserted_states


def _get_waiting_job_counts_by_profile():
    """
    Return queued job counts keyed by scanprofile id.
    """
    waiting_counts = defaultdict(int)
    rows = db.session.execute(text("""
            SELECT scanprofile_id, COUNT(*) AS waiting_jobs
              FROM jobs
             WHERE active = 0
               AND finished = 0
               AND scanprofile_id IS NOT NULL
             GROUP BY scanprofile_id
            """)).fetchall()
    for scanprofile_id, waiting_jobs in rows:
        waiting_counts[scanprofile_id] = waiting_jobs
    return waiting_counts


def _rotate_profiles_for_tick(profiles):
    """
    Rotate profile evaluation order across ticks to avoid starving later profiles.
    """
    if not profiles:
        db.app.config["scheduler_profile_cursor_id"] = 0
        return profiles

    cursor_profile_id = db.app.config.get("scheduler_profile_cursor_id", 0)
    start_index = 0

    if cursor_profile_id:
        for index, profile in enumerate(profiles):
            if profile.id == cursor_profile_id:
                start_index = (index + 1) % len(profiles)
                break

    if start_index == 0:
        return profiles
    return profiles[start_index:] + profiles[:start_index]


def _load_due_states_for_profile(
    profile,
    now_utc,
    state_limit,
    max_target_id,
):
    """
    Load due target/profile states for one profile, oldest first.

    Keep never-scanned and expired states in separate index-ordered reads.
    Combining both cases with ``OR`` and ordering through ``CASE`` forces
    SQLite to sort every eligible profile state before applying the small
    queue batch limit. On production-sized target sets that can occupy the
    scheduler for minutes without creating a job.
    """
    cutoff = now_utc - timedelta(minutes=profile.scan_cycle_minutes)
    profile_log_name = getattr(profile, "name", profile.id)
    applicability_sql = ""
    if not profile.apply_to_all:
        applicability_sql = """
            AND EXISTS (
                 SELECT 1
                   FROM scanprofiles_targets_assoc AS spta
                  WHERE spta.scanprofile_id = tss.scanprofile_id
                    AND spta.target_id = tss.target_id
            )
        """

    def select_state_ids(last_scan_filter, order_by, limit, phase):
        if limit <= 0:
            return []
        selection_started = time.perf_counter()
        _mark_queue_generation_stage(
            "due_state_selection",
            profile=profile_log_name,
            max_target_id=max_target_id,
            phase=phase,
            limit=limit,
            due_states=None,
        )
        logger.debug(
            "Create Job TASK debug: due-state selection started "
            "(profile=%s, phase=%s, limit=%s, max_target_id=%s)",
            profile_log_name,
            phase,
            limit,
            max_target_id,
        )
        # last_scan_filter and order_by are fixed internal SQL fragments.
        due_state_ids_sql = f"""
            SELECT tss.id
              FROM target_scan_states AS tss
              JOIN targets AS t
                ON t.id = tss.target_id
             WHERE tss.scanprofile_id = :profile_id
               AND t.active = 1
               AND t.id <= :max_target_id
               AND tss.working = 0
               AND {last_scan_filter}
               {applicability_sql}
             ORDER BY {order_by}
             LIMIT :limit
        """
        rows = db.session.execute(
            text(due_state_ids_sql),
            {
                "profile_id": profile.id,
                "cutoff": cutoff,
                "limit": limit,
                "max_target_id": int(max_target_id),
            },
        ).fetchall()
        logger.debug(
            "Create Job TASK debug: due-state selection finished "
            "(profile=%s, phase=%s, selected=%s, elapsed=%.2fs)",
            profile_log_name,
            phase,
            len(rows),
            time.perf_counter() - selection_started,
        )
        return [row[0] for row in rows]

    state_ids = select_state_ids(
        "tss.last_scan IS NULL",
        "tss.target_id ASC",
        state_limit,
        "never_scanned",
    )
    remaining = state_limit - len(state_ids)
    state_ids.extend(
        select_state_ids(
            "tss.last_scan <= :cutoff",
            "tss.last_scan ASC, tss.target_id ASC",
            remaining,
            "expired",
        )
    )
    if not state_ids:
        return []

    _mark_queue_generation_stage(
        "due_state_hydration",
        profile=profile_log_name,
        max_target_id=max_target_id,
        phase="hydrate",
        limit=state_limit,
        due_states=len(state_ids),
    )
    states = (
        db.session.query(TargetScanStates)
        .options(joinedload(TargetScanStates.target))
        .filter(TargetScanStates.id.in_(state_ids))
        .all()
    )
    states_by_id = {state.id: state for state in states}
    return [
        states_by_id[state_id] for state_id in state_ids if state_id in states_by_id
    ]


def _append_large_network_chunks(target, state, range_chunks):
    """
    Split a large network directly into 256-address CIDR jobs.

    The previous implementation iterated over every address and repeatedly
    merged blocks of IP objects. At the supported /16 maximum that meant
    constructing 65,536 address objects before the transaction could commit.
    """
    network = IPNetwork(target.value)
    chunk_prefix = 24 if network.version == 4 else 120
    for subnet in network.subnet(chunk_prefix):
        range_chunks.append(
            {
                "cidrs": [str(subnet)],
                "targets": [target],
                "states": [state],
            }
        )


def _merge_small_ranges_into_chunks(small_ranges, range_chunks, max_chunks=None):
    """
    Merge small IP ranges across states into 256-IP jobs.
    """
    current_block = []
    current_targets = {}
    current_states = {}
    chunks_added = 0

    def append_current_block():
        nonlocal chunks_added, current_block, current_targets, current_states
        range_chunks.append(
            {
                "cidrs": [str(cidr) for cidr in cidr_merge(current_block)],
                "targets": list(current_targets.values()),
                "states": list(current_states.values()),
            }
        )
        chunks_added += 1
        current_block = []
        current_targets = {}
        current_states = {}

    for record in sorted(small_ranges, key=lambda item: item["ips"][0]):
        if max_chunks is not None and chunks_added >= max_chunks:
            break
        for ip in record["ips"]:
            current_block.append(ip)
            current_targets[record["target"].id] = record["target"]
            current_states[id(record["state"])] = record["state"]
            if len(current_block) == JOB_TARGET_CHUNK_SIZE:
                append_current_block()

    if current_block:
        append_current_block()

    return chunks_added


def _merge_hostnames_into_chunks(hostname_records, hostname_chunks, max_chunks=None):
    """
    Merge FQDN target states into 256-host jobs.
    """
    current_hosts = []
    current_targets = {}
    current_states = {}
    chunks_added = 0

    def append_current_hosts():
        nonlocal chunks_added, current_hosts, current_targets, current_states
        hostname_chunks.append(
            {
                "hosts": list(current_hosts),
                "targets": list(current_targets.values()),
                "states": list(current_states.values()),
            }
        )
        chunks_added += 1
        current_hosts = []
        current_targets = {}
        current_states = {}

    for record in hostname_records:
        if max_chunks is not None and chunks_added >= max_chunks:
            break
        current_hosts.extend(record["hosts"])
        for target in record["targets"]:
            current_targets[target.id] = target
        for state in record["states"]:
            current_states[id(state)] = state
        if len(current_hosts) == JOB_TARGET_CHUNK_SIZE:
            append_current_hosts()

    if current_hosts:
        append_current_hosts()

    return chunks_added


def _classify_due_states_for_chunks(due_states, max_large_range_jobs=None):
    """
    Split due states by target type before final 256-item chunking.
    """
    range_chunks = []
    hostname_records = []
    small_ranges = []

    for state in due_states:
        target = state.target
        if target is None:
            continue
        if is_valid_fqdn(target.value):
            hostname_records.append(
                {"hosts": [target.value], "targets": [target], "states": [state]}
            )
        else:
            net = IPNetwork(target.value)
            if net.size > JOB_TARGET_CHUNK_SIZE:
                if (
                    max_large_range_jobs is not None
                    and len(range_chunks) >= max_large_range_jobs
                ):
                    continue
                _append_large_network_chunks(target, state, range_chunks)
            else:
                small_ranges.append(
                    {"ips": list(net), "target": target, "state": state}
                )

    return range_chunks, small_ranges, hostname_records


def _enqueue_profile_job(profile, job_value, scan_ports, scan_nses, chunk, scan_cycle):
    """
    Add one queued job and mark its linked targets/states working.
    """
    new_job = Jobs()
    new_job.uid = str(uuid.uuid4())
    new_job.job = job_value
    new_job.scanprofile_id = profile.id
    new_job.scanprofile = profile
    new_job.scanprofile_name = profile.name
    new_job.scan_ports = scan_ports
    new_job.scan_nses = scan_nses
    new_job.nmap_additional_params = profile.nmap_additional_params
    new_job.scan_unit_count = compute_scan_unit_count_list(job_value)
    new_job.priority = profile.priority or 0
    new_job.scanprofile_cycle = scan_cycle
    for target in chunk["targets"]:
        new_job.targets.append(target)
        target.working = True
    for state in chunk["states"]:
        state.working = True
    db.session.add(new_job)
    return {state.id for state in chunk["states"]}


def _enqueue_range_jobs(profile, range_chunks, scan_ports, scan_nses, scan_cycle):
    """
    Add queued range jobs and return their scheduled state IDs.
    """
    scheduled_state_ids = set()
    for chunk in range_chunks:
        job_value = ",".join(str(cidr) for cidr in cidr_merge(chunk["cidrs"]))
        scheduled_state_ids.update(
            _enqueue_profile_job(
                profile, job_value, scan_ports, scan_nses, chunk, scan_cycle
            )
        )
    return scheduled_state_ids


def _enqueue_hostname_jobs(profile, hostname_chunks, scan_ports, scan_nses, scan_cycle):
    """
    Add queued FQDN jobs and return their scheduled state IDs.
    """
    scheduled_state_ids = set()
    for chunk in hostname_chunks:
        scheduled_state_ids.update(
            _enqueue_profile_job(
                profile,
                ",".join(chunk["hosts"]),
                scan_ports,
                scan_nses,
                chunk,
                scan_cycle,
            )
        )
    return scheduled_state_ids


def _stage_jobs_for_profile(
    profile,
    due_states,
    scan_ports,
    scan_nses,
    scan_cycle,
    max_jobs=None,
):
    """
    Convert due states into queued jobs for one profile.
    """
    range_chunks, small_ranges, hostname_records = _classify_due_states_for_chunks(
        due_states,
        max_large_range_jobs=max_jobs,
    )
    hostname_chunks = []
    jobs_remaining = None
    if max_jobs is not None:
        jobs_remaining = max(0, max_jobs - len(range_chunks))

    if small_ranges and (jobs_remaining is None or jobs_remaining > 0):
        range_jobs_added = _merge_small_ranges_into_chunks(
            small_ranges,
            range_chunks,
            jobs_remaining,
        )
        if jobs_remaining is not None:
            jobs_remaining = max(0, jobs_remaining - range_jobs_added)

    if hostname_records and (jobs_remaining is None or jobs_remaining > 0):
        _merge_hostnames_into_chunks(hostname_records, hostname_chunks, jobs_remaining)

    scheduled_state_ids = _enqueue_range_jobs(
        profile, range_chunks, scan_ports, scan_nses, scan_cycle
    )
    scheduled_state_ids.update(
        _enqueue_hostname_jobs(
            profile, hostname_chunks, scan_ports, scan_nses, scan_cycle
        )
    )

    return {
        "scheduled_states": len(scheduled_state_ids),
        "range_jobs": len(range_chunks),
        "host_jobs": len(hostname_chunks),
    }


def task_create_jobs():
    """
    Keep per-profile waiting queues filled without sweeping the whole target set.

    How it works:
    - First repairs, in bounded batches, target/profile states left in
      `working` mode while no unfinished job references them anymore.
    - Creates missing target/profile runtime rows so each active target has one
      state row per applicable scan profile.
    - Reconciles each running scan-profile cycle only when its queue needs work,
      committing immediately so other profiles are never scanned under the
      same SQLite writer transaction.
    - Loads scan profiles by priority, then resumes after the last profile
      processed by the previous tick so the same profiles are not always first.
    - For each eligible profile, computes the waiting-job deficit:
      `queue_target - waiting_before`.
    - Converts that job deficit into an item load budget. A job should contain
      up to 256 items when enough targets are due; the last job may contain
      fewer than 256 only when the due list is exhausted.
    - Stages jobs through `_stage_jobs_for_profile()`: IP/CIDR and FQDN targets
      are grouped into 256-item chunks, jobs are added to the session, then only
      actually scheduled targets/states are marked `working=True`.
    - Prepares each batch under `no_autoflush`, then commits at most 256 states
      at a time. CPU-side chunking therefore never owns SQLite's writer lock,
      and scan-result reception can interleave between queue batches.
    - Stops between committed state batches when the queue-generation time
      budget is reached. A single CIDR remains atomic, so a /16 can exceed the
      soft budget slightly while its 256 /24 jobs are completed.
    - Stops once the global `SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK` budget is
      exhausted.
    """
    started_at = time.perf_counter()
    time_budget_seconds = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_TIME_BUDGET_SECONDS",
        DEFAULT_QUEUE_TIME_BUDGET_SECONDS,
    )
    generation_deadline = started_at + time_budget_seconds
    orphan_release = {"released_states": 0, "checked_states": 0}
    seeded_states = 0
    cycles_checked = 0

    # Step 1: release states stuck in working mode without an active job.
    # The called helper stays deliberately batched to protect SQLite.
    _mark_queue_generation_stage("orphan_state_release")
    orphan_started = time.perf_counter()
    if _should_run_orphan_state_release():
        orphan_release = _release_orphaned_working_states()
        logger.debug(
            "Create Job TASK debug: orphan-state release completed in %.2fs (checked_states=%s, released_states=%s)",
            time.perf_counter() - orphan_started,
            orphan_release["checked_states"],
            orphan_release["released_states"],
        )
    else:
        logger.debug(
            "Create Job TASK debug: orphan-state release skipped (cooldown active)"
        )

    # Step 2: create missing target/profile runtime rows.
    # Without those rows, an active target cannot enter the scheduler.
    _mark_queue_generation_stage("state_sync")
    sync_started = time.perf_counter()
    seeded_states = _sync_missing_scan_states(deadline=generation_deadline)
    logger.debug(
        "Create Job TASK debug: state sync completed in %.2fs (seeded_states=%s)",
        time.perf_counter() - sync_started,
        seeded_states,
    )

    # Step 3: read queue-fill limits.
    # queue_target and max_new_jobs_per_tick are job-count limits.
    # state_batch_size is a target/profile-state read limit.
    queue_target = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_TARGET_JOBS_PER_PROFILE",
        DEFAULT_QUEUE_TARGET_JOBS_PER_PROFILE,
    )
    configured_state_batch_size = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_STATE_BATCH_SIZE",
        DEFAULT_QUEUE_STATE_BATCH_SIZE,
    )
    # This is a transaction-size safety boundary, not a throughput limit.
    # Older production configs may still contain 4096 from the previous
    # implementation; cap them so result reception is never placed behind a
    # multi-thousand-state scheduler transaction.
    state_batch_size = min(
        configured_state_batch_size,
        JOB_TARGET_CHUNK_SIZE,
    )
    max_new_jobs_per_tick = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK",
        DEFAULT_MAX_NEW_JOBS_PER_TICK,
    )
    if configured_state_batch_size > state_batch_size:
        logger.warning(
            "Create Job TASK: capped SCHEDULER_QUEUE_STATE_BATCH_SIZE from %s to %s "
            "to protect scan-result writes",
            configured_state_batch_size,
            state_batch_size,
        )

    # Step 4: load queue metadata once for this tick.
    # waiting_counts avoids recounting the DB after each profile.
    _mark_queue_generation_stage("queue_metadata")
    metadata_started = time.perf_counter()
    profiles = (
        db.session.query(ScanProfiles)
        .order_by(ScanProfiles.priority.desc(), ScanProfiles.id.asc())
        .all()
    )
    waiting_counts = _get_waiting_job_counts_by_profile()
    now = utcnow_naive()
    logger.debug(
        "Create Job TASK debug: loaded queue metadata in %.2fs (profiles=%s, queued_profiles=%s)",
        time.perf_counter() - metadata_started,
        len(profiles),
        len(waiting_counts),
    )
    # Simple rotation: the next tick resumes after the last processed profile.
    profiles = _rotate_profiles_for_tick(profiles)

    # End-of-tick counters used only for logs and the returned summary.
    totals = {
        "scheduled_states": 0,
        "range_jobs": 0,
        "host_jobs": 0,
    }
    profiles_with_jobs = 0
    profiles_without_ports = 0
    profiles_without_cycle = 0
    profiles_already_full = 0
    profiles_without_due_states = 0
    budget_exhausted = False
    time_budget_exhausted = False
    profile_summaries = []
    last_processed_profile_id = 0
    stop_queue_fill = False
    queue_batches_attempted = 0

    fill_started = time.perf_counter()
    for profile_index, profile in enumerate(profiles, start=1):
        jobs_created_so_far = totals["range_jobs"] + totals["host_jobs"]
        if _queue_time_budget_reached(
            generation_deadline,
            max(jobs_created_so_far, queue_batches_attempted),
        ):
            time_budget_exhausted = True
            break
        last_processed_profile_id = profile.id

        # Step 5: skip profiles that cannot produce executable Nmap jobs.
        # A job without ports or scan frequency is not actionable.
        scan_ports = _serialize_profile_ports(profile)
        if not scan_ports:
            profiles_without_ports += 1
            logger.warning(
                "Create Job TASK: skipping profile %s because it has no ports",
                profile.name,
            )
            continue

        cycle_minutes = profile.scan_cycle_minutes
        if not cycle_minutes or cycle_minutes <= 0:
            profiles_without_cycle += 1
            logger.warning(
                "Create Job TASK: skipping profile %s because scan_cycle_minutes is not set",
                profile.name,
            )
            continue

        # Step 6: check whether this profile queue needs more jobs.
        # queue_deficit is a missing-job count, not a target count.
        waiting_before = waiting_counts.get(profile.id, 0)
        queue_deficit = queue_target - waiting_before
        if queue_deficit <= 0:
            profiles_already_full += 1
            continue

        logger.info(
            "Create Job TASK progress: profile=%s profile_index=%s/%s "
            "queue=%s/%s deficit=%s; reconciling cycle",
            profile.name,
            profile_index,
            len(profiles),
            waiting_before,
            queue_target,
            queue_deficit,
        )
        _mark_queue_generation_stage(
            "cycle_reconcile",
            profile=profile.name,
            profile_index=profile_index,
            profile_total=len(profiles),
            cycle_id=None,
            max_target_id=None,
            batch=None,
            phase=None,
            limit=None,
            due_states=None,
            queue_waiting=waiting_before,
            queue_target=queue_target,
        )

        # Step 7: reconcile only the profile that is about to generate work.
        # Commit immediately so aggregate scans for different profiles never
        # share one long-lived SQLite writer transaction.
        scan_cycle = get_running_scanprofile_cycle(profile.id)
        if scan_cycle is not None:
            cycle_started = time.perf_counter()
            # Cycle aggregation is query-heavy. Prevent cycle attribute changes
            # from autoflushing and reserving SQLite's writer during those reads.
            with db.session.no_autoflush:
                scan_cycle = reconcile_scanprofile_cycle(
                    profile.id,
                    cycle=scan_cycle,
                    now=now,
                    prune_history=False,
                )
            cycles_checked += 1
            cycle_is_running = scan_cycle is not None and scan_cycle.status == "running"
            db.session.commit()
            logger.debug(
                "Create Job TASK debug: profile %s cycle reconciled in %.2fs",
                profile.name,
                time.perf_counter() - cycle_started,
            )
            if not cycle_is_running:
                scan_cycle = None

        # A running cycle keeps its persisted target-ID boundary. For a new
        # cycle, capture the current high-water mark before loading due states.
        # Targets inserted after this point wait for the next cycle.
        cycle_max_target_id = (
            scan_cycle.max_target_id
            if scan_cycle is not None and scan_cycle.max_target_id is not None
            else get_current_max_target_id()
        )
        logger.info(
            "Create Job TASK progress: profile=%s cycle_id=%s max_target_id=%s "
            "cycle_targets=%s/%s cycle_scan_units=%s/%s queue=%s/%s",
            profile.name,
            getattr(scan_cycle, "id", None),
            cycle_max_target_id,
            getattr(scan_cycle, "completed_target_count", 0),
            getattr(scan_cycle, "target_count", 0),
            getattr(scan_cycle, "completed_scan_unit_count", 0),
            getattr(scan_cycle, "scan_unit_count", 0),
            waiting_before,
            queue_target,
        )
        _mark_queue_generation_stage(
            "due_state_load",
            profile=profile.name,
            profile_index=profile_index,
            profile_total=len(profiles),
            cycle_id=getattr(scan_cycle, "id", None),
            max_target_id=cycle_max_target_id,
            batch=1,
            phase=None,
            limit=state_batch_size,
            due_states=None,
            queue_waiting=waiting_before,
            queue_target=queue_target,
        )
        scan_nses = _serialize_profile_nses(profile)
        profile_counts = {
            "scheduled_states": 0,
            "range_jobs": 0,
            "host_jobs": 0,
        }
        batch_number = 0

        # Step 8: fill the profile queue through independent 256-state
        # transactions. The time and job limits are checked after every commit.
        while queue_deficit > 0:
            jobs_created_so_far = totals["range_jobs"] + totals["host_jobs"]
            if _queue_time_budget_reached(
                generation_deadline,
                max(jobs_created_so_far, queue_batches_attempted),
            ):
                time_budget_exhausted = True
                stop_queue_fill = True
                break

            jobs_available = max_new_jobs_per_tick - jobs_created_so_far
            if jobs_available <= 0:
                budget_exhausted = True
                stop_queue_fill = True
                break

            job_limit = min(queue_deficit, jobs_available)
            # A state batch may create several jobs for CIDRs, but never stages
            # more than 256 target/profile rows in one transaction.
            state_limit = min(
                state_batch_size,
                job_limit * JOB_TARGET_CHUNK_SIZE,
            )
            due_started = time.perf_counter()
            due_states = _load_due_states_for_profile(
                profile,
                now,
                state_limit,
                cycle_max_target_id,
            )
            queue_batches_attempted += 1
            due_elapsed = time.perf_counter() - due_started
            if not due_states:
                if profile_counts["range_jobs"] + profile_counts["host_jobs"] == 0:
                    profiles_without_due_states += 1
                logger.debug(
                    "Create Job TASK debug: profile %s has no due states "
                    "(waiting=%s, deficit=%s, load=%.2fs)",
                    profile.name,
                    waiting_before,
                    queue_deficit,
                    due_elapsed,
                )
                break

            # A new cycle is committed before CPU-side job preparation. This
            # avoids retaining the writer lock acquired by its required flush.
            if scan_cycle is None:
                scan_cycle = get_or_create_running_cycle(
                    profile.id,
                    now=now,
                    max_target_id=cycle_max_target_id,
                    reconcile=False,
                )
                profile.current_cycle_id = scan_cycle.id
                db.session.commit()

            logger.info(
                "Create Job TASK progress: profile=%s batch=%s cycle_id=%s "
                "due_states=%s queue=%s/%s; staging jobs",
                profile.name,
                batch_number + 1,
                getattr(scan_cycle, "id", None),
                len(due_states),
                waiting_before,
                queue_target,
            )
            _mark_queue_generation_stage(
                "job_staging",
                profile=profile.name,
                cycle_id=getattr(scan_cycle, "id", None),
                max_target_id=cycle_max_target_id,
                batch=batch_number + 1,
                phase=None,
                limit=state_limit,
                due_states=len(due_states),
                queue_waiting=waiting_before,
                queue_target=queue_target,
            )

            # Transform the batch without autoflush. The only write window is
            # the explicit commit immediately following this block.
            stage_started = time.perf_counter()
            with db.session.no_autoflush:
                job_counts = _stage_jobs_for_profile(
                    profile,
                    due_states,
                    scan_ports,
                    scan_nses,
                    scan_cycle,
                    max_jobs=job_limit,
                )
            stage_elapsed = time.perf_counter() - stage_started

            _mark_queue_generation_stage(
                "batch_commit",
                profile=profile.name,
                cycle_id=getattr(scan_cycle, "id", None),
                max_target_id=cycle_max_target_id,
                batch=batch_number + 1,
                phase=None,
                limit=state_limit,
                due_states=len(due_states),
                queue_waiting=waiting_before,
                queue_target=queue_target,
            )
            commit_started = time.perf_counter()
            db.session.commit()
            commit_elapsed = time.perf_counter() - commit_started
            batch_number += 1

            new_jobs = job_counts["range_jobs"] + job_counts["host_jobs"]
            waiting_after = waiting_before + new_jobs
            waiting_counts[profile.id] = waiting_after
            for counter_name in totals:
                totals[counter_name] += job_counts[counter_name]
                profile_counts[counter_name] += job_counts[counter_name]

            jobs_created_this_tick = totals["range_jobs"] + totals["host_jobs"]
            _record_queue_generation_commit(
                new_jobs,
                profile=profile.name,
                cycle_id=getattr(scan_cycle, "id", None),
                max_target_id=cycle_max_target_id,
                batch=batch_number,
                phase=None,
                limit=state_limit,
                due_states=len(due_states),
                queue_waiting=waiting_after,
                queue_target=queue_target,
            )
            logger.info(
                "Create Job TASK generated: profile=%s batch=%s cycle_id=%s "
                "jobs_generated=%s range_jobs=%s host_jobs=%s "
                "states_scheduled=%s queue=%s/%s tick_jobs=%s/%s "
                "elapsed=%.2fs (load=%.2fs stage=%.2fs commit=%.2fs)",
                profile.name,
                batch_number,
                getattr(scan_cycle, "id", None),
                new_jobs,
                job_counts["range_jobs"],
                job_counts["host_jobs"],
                job_counts["scheduled_states"],
                waiting_after,
                queue_target,
                jobs_created_this_tick,
                max_new_jobs_per_tick,
                due_elapsed + stage_elapsed + commit_elapsed,
                due_elapsed,
                stage_elapsed,
                commit_elapsed,
            )

            if new_jobs <= 0:
                break

            waiting_before = waiting_after
            queue_deficit = queue_target - waiting_after

            jobs_created_so_far = totals["range_jobs"] + totals["host_jobs"]
            if jobs_created_so_far >= max_new_jobs_per_tick:
                budget_exhausted = True
                stop_queue_fill = True
                break
            if _queue_time_budget_reached(generation_deadline, jobs_created_so_far):
                time_budget_exhausted = True
                stop_queue_fill = True
                break

        profile_job_count = profile_counts["range_jobs"] + profile_counts["host_jobs"]
        if profile_job_count > 0:
            profiles_with_jobs += 1
            profile_summaries.append(
                f"{profile.name}={profile_job_count}"
                f"(range:{profile_counts['range_jobs']},"
                f"host:{profile_counts['host_jobs']},"
                f"states:{profile_counts['scheduled_states']},"
                f"queued:{waiting_counts[profile.id]})"
            )

        if stop_queue_fill:
            break

    if not time_budget_exhausted and _queue_time_budget_reached(
        generation_deadline,
        max(totals["range_jobs"] + totals["host_jobs"], queue_batches_attempted),
    ):
        time_budget_exhausted = True

    logger.debug(
        "Create Job TASK debug: queue fill completed in %.2fs",
        time.perf_counter() - fill_started,
    )
    # Save the inter-tick profile rotation cursor.
    if last_processed_profile_id:
        db.app.config["scheduler_profile_cursor_id"] = last_processed_profile_id

    # Step 15: build a compact summary for logs and observability.
    total_jobs_created = totals["range_jobs"] + totals["host_jobs"]
    summary_log = (
        "Create Job TASK: %s jobs created across %s profiles (%s range, %s host); "
        "%s target/profile states scheduled; queue_target=%s; state_batch=%s; "
        "time_budget=%ss; "
        "%s state rows seeded; %s orphan states released; %s profiles already full; "
        "%s profiles had no due states; %s profiles skipped without ports; "
        "%s profiles skipped without scan frequency; %s cycles checked; "
        "budget_exhausted=%s; time_budget_exhausted=%s"
    )
    summary_args = (
        total_jobs_created,
        profiles_with_jobs,
        totals["range_jobs"],
        totals["host_jobs"],
        totals["scheduled_states"],
        queue_target,
        state_batch_size,
        time_budget_seconds,
        seeded_states,
        orphan_release["released_states"],
        profiles_already_full,
        profiles_without_due_states,
        profiles_without_ports,
        profiles_without_cycle,
        cycles_checked,
        budget_exhausted,
        time_budget_exhausted,
    )
    if total_jobs_created == 0:
        logger.warning(summary_log, *summary_args)
    else:
        logger.info(summary_log, *summary_args)

    if profile_summaries:
        logger.info("Create Job TASK profiles: %s", "; ".join(profile_summaries))
    logger.debug(
        "Create Job TASK debug: total create_jobs runtime %.2fs",
        time.perf_counter() - started_at,
    )
    # Return counters useful for tests and generic scheduler logs.
    return {
        "jobs_created": total_jobs_created,
        "range_jobs": totals["range_jobs"],
        "host_jobs": totals["host_jobs"],
        "states_scheduled": totals["scheduled_states"],
        "profiles_total": len(profiles),
        "profiles_with_jobs": profiles_with_jobs,
        "profiles_full": profiles_already_full,
        "profiles_without_due_states": profiles_without_due_states,
        "profiles_without_ports": profiles_without_ports,
        "profiles_without_cycle": profiles_without_cycle,
        "job_budget_exhausted": budget_exhausted,
        "seeded_states": seeded_states,
        "cycles_checked": cycles_checked,
        "orphan_states_checked": orphan_release["checked_states"],
        "orphan_states_released": orphan_release["released_states"],
        "time_budget_seconds": time_budget_seconds,
        "time_budget_exhausted": time_budget_exhausted,
    }


def task_sync_queued_profile_jobs():
    """
    Gradually converge queued job snapshots to their scan profile settings.

    Jobs are immutable while running or after completion. Queued jobs are
    updated in bounded batches so profile edits do not hold the database lock
    for the whole backlog.
    """
    started_at = time.perf_counter()
    batch_size = _get_scheduler_int_config(
        "SCHEDULER_PRIORITY_RETAG_BATCH_SIZE",
        DEFAULT_PRIORITY_RETAG_BATCH_SIZE,
    )
    profiles = (
        db.session.query(ScanProfiles)
        .filter(ScanProfiles.priority_retag_pending == True)
        .order_by(ScanProfiles.priority.desc(), ScanProfiles.id.asc())
        .all()
    )
    if not profiles:
        logger.debug("Profile sync TASK: no pending profile")
        return {"profiles_pending": 0, "jobs_synchronized": 0}

    total_synchronized = 0
    completed_profiles = 0
    for profile in profiles:
        updated = (
            db.session.execute(
                text("""
                    UPDATE jobs
                       SET priority = :priority,
                           scanprofile_name = :profile_name,
                           scan_ports = :scan_ports,
                           scan_nses = :scan_nses,
                           nmap_additional_params = :nmap_additional_params
                     WHERE id IN (
                            SELECT id
                              FROM jobs
                             WHERE scanprofile_id = :profile_id
                               AND active = 0
                               AND finished = 0
                               AND (
                                  priority != :priority
                               OR COALESCE(scanprofile_name, '') != COALESCE(:profile_name, '')
                               OR COALESCE(scan_ports, '') != COALESCE(:scan_ports, '')
                               OR COALESCE(scan_nses, '') != COALESCE(:scan_nses, '')
                               OR COALESCE(nmap_additional_params, '') != COALESCE(:nmap_additional_params, '')
                             )
                             ORDER BY job_creation ASC
                             LIMIT :batch_size
                       )
                    """),
                {
                    "priority": int(profile.priority or 0),
                    "profile_id": profile.id,
                    "batch_size": batch_size,
                    "profile_name": profile.name,
                    "scan_ports": _serialize_profile_ports(profile),
                    "scan_nses": _serialize_profile_nses(profile),
                    "nmap_additional_params": profile.nmap_additional_params,
                },
            ).rowcount
            or 0
        )
        total_synchronized += updated

        has_remaining = db.session.execute(
            text("""
                SELECT 1
                  FROM jobs
                 WHERE scanprofile_id = :profile_id
                   AND active = 0
                   AND finished = 0
                   AND (
                        priority != :priority
                     OR COALESCE(scanprofile_name, '') != COALESCE(:profile_name, '')
                     OR COALESCE(scan_ports, '') != COALESCE(:scan_ports, '')
                     OR COALESCE(scan_nses, '') != COALESCE(:scan_nses, '')
                     OR COALESCE(nmap_additional_params, '') != COALESCE(:nmap_additional_params, '')
                   )
                 LIMIT 1
                """),
            {
                "profile_id": profile.id,
                "priority": int(profile.priority or 0),
                "profile_name": profile.name,
                "scan_ports": _serialize_profile_ports(profile),
                "scan_nses": _serialize_profile_nses(profile),
                "nmap_additional_params": profile.nmap_additional_params,
            },
        ).fetchone()
        if has_remaining is None:
            profile.priority_retag_pending = False
            completed_profiles += 1

        db.session.commit()
        logger.info(
            "Profile sync TASK: profile %s synchronized %s queued jobs; pending=%s",
            profile.name,
            updated,
            bool(has_remaining),
        )

    logger.info(
        "Profile sync TASK: synchronized %s queued jobs across %s profiles; "
        "completed_profiles=%s; batch_size=%s; elapsed=%.2fs",
        total_synchronized,
        len(profiles),
        completed_profiles,
        batch_size,
        time.perf_counter() - started_at,
    )
    return {
        "profiles_pending": len(profiles),
        "profiles_completed": completed_profiles,
        "jobs_synchronized": total_synchronized,
        "batch_size": batch_size,
    }


def _export_job_state(job_data):
    """Copy persisted job export fields into a transaction-free dictionary."""
    return {
        "id": job_data.id,
        "uid": job_data.uid,
        "exported": bool(job_data.exported),
        "task_uid": job_data.meili_task_uid,
        "submitted": int(job_data.meili_documents_submitted or 0),
        "total": job_data.meili_documents_total,
    }


def _load_job_export_documents(export_context, job_uid):
    """Load one immutable job result and build matching Meili/Kvrocks docs."""
    filepath = os.path.join(
        export_context.input_dir,
        job_uid[0],
        f"{job_uid}.json",
    )
    with open(filepath, "r", encoding="utf-8") as json_handle:
        data = json.load(json_handle)
    if isinstance(data, dict):
        scan_results = [data]
    elif isinstance(data, list):
        scan_results = data
    else:
        scan_results = []

    meili_documents = []
    kvrocks_documents = []
    for item in scan_results:
        for object_to_save in _split_scan_result_by_port(item):
            parsed_doc = parse_json(
                object_to_save,
                export_context.parser_config,
                tag_rules=export_context.active_tag_rules,
            )
            if parsed_doc is None:
                continue
            meili_documents.append(object_to_save)
            kvrocks_documents.append(parsed_doc)
    return meili_documents, kvrocks_documents


def _reset_meili_export_state(job_state):
    """Forget failed submission state so entire job can be safely upserted again."""
    job_state["task_uid"] = None
    job_state["submitted"] = 0
    job_state["total"] = None


def _persist_meili_export_states(job_states):
    """Persist external Meilisearch state before scheduler yields control."""
    for job_state in job_states:
        db.session.query(Jobs).filter(Jobs.id == job_state["id"]).update(
            {
                Jobs.exported: job_state["exported"],
                Jobs.meili_task_uid: job_state["task_uid"],
                Jobs.meili_documents_submitted: job_state["submitted"],
                Jobs.meili_documents_total: job_state["total"],
            },
            synchronize_session=False,
        )
    db.session.commit()


def _finalize_ready_export_jobs(job_states, export_context):
    """Write Kvrocks only for jobs whose complete Meili input has succeeded."""
    documents_exported = 0
    jobs_exported = 0
    for job_state in job_states:
        job_state["task_uid"] = None
        total = job_state["total"]
        if total is None or job_state["submitted"] < total:
            continue

        meili_documents, kvrocks_documents = _load_job_export_documents(
            export_context,
            job_state["uid"],
        )
        if len(meili_documents) != total:
            raise MeiliExportTaskError(
                f"Job {job_state['uid']} document count changed after Meilisearch "
                f"submission: expected {total}, found {len(meili_documents)}"
            )
        for offset in range(0, len(kvrocks_documents), MEILI_EXPORT_BATCH_SIZE):
            export_context.kvrocks_idx.add_documents_batch(
                kvrocks_documents[offset : offset + MEILI_EXPORT_BATCH_SIZE]
            )
        documents_exported += len(kvrocks_documents)
        jobs_exported += 1
        job_state["exported"] = True
        _reset_meili_export_state(job_state)
    return documents_exported, jobs_exported


def _process_persisted_meili_task(
    export_context,
    task_uid,
    job_states,
):
    """Check one task once; never resubmit or write Kvrocks while pending."""
    completed_task = export_context.meili_idx.get_task(task_uid)
    task_status = str(getattr(completed_task, "status", "")).lower()
    if task_status in ("enqueued", "processing"):
        return {
            "status": task_status,
            "documents_exported": 0,
            "jobs_exported": 0,
        }
    if task_status != "succeeded":
        for job_state in job_states:
            _reset_meili_export_state(job_state)
        return {
            "status": task_status or "unknown",
            "error": getattr(completed_task, "error", None),
            "documents_exported": 0,
            "jobs_exported": 0,
        }

    documents_exported, jobs_exported = _finalize_ready_export_jobs(
        job_states,
        export_context,
    )
    return {
        "status": "succeeded",
        "documents_exported": documents_exported,
        "jobs_exported": jobs_exported,
    }


def _load_export_job_states(task_uid=None):
    """Load eligible job state, optionally restricted to one Meili task."""
    query = db.session.query(
        Jobs.id,
        Jobs.uid,
        Jobs.exported,
        Jobs.meili_task_uid,
        Jobs.meili_documents_submitted,
        Jobs.meili_documents_total,
    ).filter(
        Jobs.active == False,
        Jobs.exported == False,
        Jobs.finished == True,
    )
    if task_uid is None:
        query = query.filter(Jobs.meili_task_uid == None).order_by(Jobs.id)
    else:
        query = query.filter(Jobs.meili_task_uid == task_uid).order_by(Jobs.id)
    states = [_export_job_state(row) for row in query.yield_per(100)]
    db.session.commit()
    db.session.remove()
    return states


def _export_summary(
    jobs_scanned,
    documents_exported=0,
    batches=0,
    jobs_exported=0,
    **flags,
):
    """Return consistent scheduler metrics for every export state transition."""
    summary = {
        "jobs_scanned": jobs_scanned,
        "documents_exported": documents_exported,
        "batches": batches,
        "jobs_marked_exported": jobs_exported,
    }
    if flags.get("pending_tasks"):
        summary["meili_tasks_pending"] = flags["pending_tasks"]
    if flags.get("errors"):
        summary["errors"] = flags["errors"]
    return summary


def _build_export_context():
    """Load immutable config and parser state for one export transition."""
    meili_idx = db.app.config.get("MEILI_IDX")
    kvrocks_idx = db.app.config.get("KVROCKS_IDX")
    active_tag_rules = compile_tag_rule_records(
        db.session.query(TagRules).filter(TagRules.active == True).all()
    )
    parser_config = dict(db.app.config)
    ensure_default_collected_headers(db.session)
    ensure_rule_required_headers(db.session)
    parser_config["HTTP_HEADER_COLLECTION"] = {
        str(row.header_name or "").strip().lower(): bool(row.collect_value)
        for row in db.session.query(CollectedHeaders).all()
        if str(row.header_name or "").strip()
    }
    return ExportContext(
        meili_idx=meili_idx,
        kvrocks_idx=kvrocks_idx,
        input_dir=os.path.expanduser(db.app.config.get("JSON_FOLDER")),
        parser_config=parser_config,
        active_tag_rules=active_tag_rules,
    )


def _load_pending_meili_task_uids():
    """Return durable unfinished task UIDs and release SQLite read state."""
    task_uids = [
        row[0]
        for row in db.session.query(Jobs.meili_task_uid)
        .filter(
            Jobs.meili_task_uid != None,
            Jobs.active == False,
            Jobs.finished == True,
            Jobs.exported == False,
        )
        .distinct()
        .order_by(Jobs.meili_task_uid)
    ]
    db.session.commit()
    db.session.remove()
    return task_uids


def _resume_persisted_export(export_context, pending_task_uids):
    """Advance oldest persisted task once without resubmitting its documents."""
    if len(pending_task_uids) > 1:
        logger.warning(
            "Multiple persisted Meilisearch export tasks found: %s",
            pending_task_uids,
        )
    task_uid = pending_task_uids[0]
    job_states = _load_export_job_states(task_uid)
    result = _process_persisted_meili_task(
        export_context,
        task_uid,
        job_states,
    )
    if result["status"] in ("enqueued", "processing"):
        logger.info(
            "Meilisearch export task %s remains %s; deferring Kvrocks "
            "and job completion to next scheduler tick",
            task_uid,
            result["status"],
        )
        return _export_summary(len(job_states), pending_tasks=1)

    _persist_meili_export_states(job_states)
    if result["status"] != "succeeded":
        logger.error(
            "Meilisearch export task %s ended with status %s: %s",
            task_uid,
            result["status"],
            result.get("error") or "no error details",
        )
        return _export_summary(len(job_states), errors=1)
    return _export_summary(
        len(job_states),
        documents_exported=result["documents_exported"],
        jobs_exported=result["jobs_exported"],
    )


def _prepare_meili_export_batch(export_context, job_states):
    """Build next bounded batch while finalizing already-confirmed jobs."""
    batch_state = {
        "documents": [],
        "jobs": [],
        "ready_documents": 0,
        "ready_jobs": 0,
    }
    ready_states = []
    for job_state in job_states:
        meili_documents, _kvrocks_documents = _load_job_export_documents(
            export_context,
            job_state["uid"],
        )
        document_total = len(meili_documents)
        if job_state["total"] is not None and job_state["total"] != document_total:
            logger.warning(
                "Job %s document count changed from %s to %s; restarting "
                "Meilisearch submission",
                job_state["uid"],
                job_state["total"],
                document_total,
            )
            job_state["submitted"] = 0
        job_state["total"] = document_total
        job_state["submitted"] = min(job_state["submitted"], document_total)

        if job_state["submitted"] >= document_total:
            ready_states.append(job_state)
            continue

        capacity = MEILI_EXPORT_BATCH_SIZE - len(batch_state["documents"])
        contribution = min(capacity, document_total - job_state["submitted"])
        start = job_state["submitted"]
        batch_state["documents"].extend(meili_documents[start : start + contribution])
        job_state["submitted"] += contribution
        batch_state["jobs"].append(job_state)
        if len(batch_state["documents"]) >= MEILI_EXPORT_BATCH_SIZE:
            break

    if ready_states:
        ready_counts = _finalize_ready_export_jobs(ready_states, export_context)
        _persist_meili_export_states(ready_states)
        batch_state["ready_documents"], batch_state["ready_jobs"] = ready_counts
    return batch_state


def _submit_meili_export_batch(export_context, jobs_scanned, batch_state):
    """Submit and persist one batch, then yield until the next scheduler tick."""
    task_uid = _get_meili_task_uid(
        export_context.meili_idx.add_documents(batch_state["documents"])
    )
    for job_state in batch_state["jobs"]:
        job_state["task_uid"] = task_uid
    _persist_meili_export_states(batch_state["jobs"])
    logger.info(
        "Meilisearch export task %s submitted: documents=%s jobs=%s",
        task_uid,
        len(batch_state["documents"]),
        len(batch_state["jobs"]),
    )
    return _export_summary(
        jobs_scanned,
        documents_exported=batch_state["ready_documents"],
        batches=1,
        jobs_exported=batch_state["ready_jobs"],
        pending_tasks=1,
    )


def _advance_new_meili_export(export_context):
    """Prepare and submit one new batch when no server task is outstanding."""
    job_states = _load_export_job_states()
    if not job_states:
        return _export_summary(0)
    batch_state = _prepare_meili_export_batch(export_context, job_states)
    if not batch_state["documents"]:
        return _export_summary(
            len(job_states),
            documents_exported=batch_state["ready_documents"],
            jobs_exported=batch_state["ready_jobs"],
        )
    return _submit_meili_export_batch(
        export_context,
        len(job_states),
        batch_state,
    )


def task_export_to_dbs():
    """Advance durable Meilisearch-first export state by at most one batch."""
    export_context = _build_export_context()
    pending_task_uids = _load_pending_meili_task_uids()

    try:
        if pending_task_uids:
            return _resume_persisted_export(export_context, pending_task_uids)
        return _advance_new_meili_export(export_context)
    except (MeilisearchError, MeiliExportTaskError, HTTPError) as error:
        db.session.rollback()
        logger.error("Unable to advance export state: %s", error)
        return _export_summary(0, errors=1)
    finally:
        db.session.remove()


def _build_due_report(report, run_at):
    """
    Execute a report query and return its Markdown body.
    """
    from .views import KVSearchView  # pylint: disable=import-outside-toplevel

    from_dt, to_dt = compute_report_interval(report, run_at=run_at)
    results = KVSearchView().execute_search(
        report.query,
        datetime_to_epoch(from_dt),
        datetime_to_epoch(to_dt),
    )
    if not results.get("status"):
        raise ValueError(results.get("msg_error") or "Invalid report query")

    indexer = db.app.config.get("KVROCKS_IDX") or KVrocksIndexer(
        db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
    )
    per_ip_ports, port_counter = collect_report_ports(
        indexer,
        results.get("results") or {},
    )
    per_ip_tags = collect_report_tags(
        indexer,
        results.get("results") or {},
    )
    per_ip_requested_fqdns = collect_report_requested_fqdns(
        indexer,
        results.get("results") or {},
    )
    per_ip_pdns_fqdns = collect_report_passive_dns_fqdns(
        db.app.config,
        (results.get("results") or {}).keys(),
        per_ip_requested_fqdns,
    )
    new_open_ports = {}
    previous_from_dt, previous_to_dt = compute_previous_report_interval(
        report,
        from_dt,
        to_dt,
    )
    if previous_from_dt and previous_to_dt:
        previous_results = KVSearchView().execute_search(
            report.query,
            datetime_to_epoch(previous_from_dt),
            datetime_to_epoch(previous_to_dt),
        )
        if not previous_results.get("status"):
            raise ValueError(
                previous_results.get("msg_error") or "Invalid previous report query"
            )
        previous_per_ip_ports, _previous_port_counter = collect_report_ports(
            indexer,
            previous_results.get("results") or {},
        )
        new_open_ports = compute_new_open_ports(
            per_ip_ports,
            previous_per_ip_ports,
        )
    markdown = build_report_markdown(
        report,
        results,
        per_ip_ports,
        port_counter,
        from_dt,
        to_dt,
        per_ip_tags=per_ip_tags,
        per_ip_requested_fqdns=per_ip_requested_fqdns,
        per_ip_pdns_fqdns=per_ip_pdns_fqdns,
        new_open_ports=new_open_ports,
    )
    return markdown, to_dt


def task_run_due_reports():
    """
    Send active scheduled reports whose next run is due.
    """
    if not str(db.app.config.get("REPORT_SMTP_HOST", "") or "").strip():
        return {"reports_due": 0, "reports_sent": 0, "smtp_enabled": False}

    now = utcnow_naive()
    due_reports = (
        db.session.query(Reports)
        .filter(
            Reports.active == True,
            Reports.next_run_at != None,
            Reports.next_run_at <= now,
        )
        .order_by(Reports.next_run_at.asc())
        .all()
    )
    if not due_reports:
        return {"reports_due": 0, "reports_sent": 0, "smtp_enabled": True}

    sent_reports = 0
    for report in due_reports:
        try:
            markdown, to_dt = _build_due_report(report, now)
            send_report_markdown(db.app.config, report, markdown)
            report.last_run_at = to_dt
            report.next_run_at = compute_next_report_run(report, now=to_dt)
            db.session.commit()
            sent_reports += 1
        except Exception as error:  # pylint: disable=broad-except
            db.session.rollback()
            logger.exception("Scheduled report %s failed: %s", report.id, error)

    if sent_reports:
        logger.info("Reports TASK: %s scheduled reports sent", sent_reports)
    return {
        "reports_due": len(due_reports),
        "reports_sent": sent_reports,
        "smtp_enabled": True,
    }


def task_cleanup_jobs():
    """
    This procedure will delete both Jobs from DB and Files
    """

    job_scavenge = db.app.config.get("JOB_SCAVENGE")
    json_folder = os.path.expanduser(db.app.config.get("JSON_FOLDER"))
    deleted_jobs = 0
    deleted_job_files = 0
    missing_job_files = 0
    file_delete_errors = 0

    job_snapshots = list(
        db.session.query(Jobs.id, Jobs.uid).filter(
            Jobs.active == False,
            Jobs.exported == True,
            Jobs.finished == True,
            Jobs.job_end <= utcnow_naive() - timedelta(days=job_scavenge),
        )
    )

    for job_data in job_snapshots:
        filepath = os.path.join(
            json_folder,
            job_data.uid[0],
            f"{job_data.uid}.json",
        )
        try:
            os.remove(filepath)
            deleted_job_files += 1
        except FileNotFoundError:
            missing_job_files += 1
        except OSError as err:
            file_delete_errors += 1
            logger.error("Unable to delete job file %s: %s", filepath, err)

    stale_job_ids = [job_data.id for job_data in job_snapshots]
    if stale_job_ids:
        db.session.execute(
            assoc_jobs_targets.delete().where(
                assoc_jobs_targets.c.job_id.in_(stale_job_ids)
            )
        )
        deleted_jobs = (
            db.session.query(Jobs)
            .filter(Jobs.id.in_(stale_job_ids))
            .delete(synchronize_session=False)
        )

    if deleted_jobs:
        db.session.commit()
        logger.info(
            "Cleanup Job TASK: %s jobs removed; %s files deleted; %s files already absent; %s file delete errors",
            deleted_jobs,
            deleted_job_files,
            missing_job_files,
            file_delete_errors,
        )
    return {
        "jobs_removed": deleted_jobs,
        "files_deleted": deleted_job_files,
        "files_missing": missing_job_files,
        "file_delete_errors": file_delete_errors,
    }


def task_cleanup_export_jobs():
    """
    Delete old asynchronous export files from the export jobs directory.
    """
    export_jobs_folder = os.path.expanduser(db.app.config.get("EXPORT_JOBS_FOLDER"))
    retention_days = int(db.app.config.get("EXPORT_JOBS_RETENTION_DAYS", 10))
    cutoff = utcnow_aware() - timedelta(days=retention_days)
    deleted_files = 0
    delete_errors = 0

    os.makedirs(export_jobs_folder, exist_ok=True)

    for filename in os.listdir(export_jobs_folder):
        filepath = os.path.join(export_jobs_folder, filename)
        try:
            modified_at = datetime.fromtimestamp(
                os.path.getmtime(filepath), tz=timezone.utc
            )
        except FileNotFoundError:
            continue

        if modified_at > cutoff:
            continue

        try:
            if os.path.isdir(filepath):
                shutil.rmtree(filepath)
            else:
                os.remove(filepath)
            deleted_files += 1
        except OSError as err:
            delete_errors += 1
            logger.error("Unable to delete export job artifact %s: %s", filepath, err)

    if deleted_files or delete_errors:
        logger.info(
            "Cleanup Export TASK: %s export artifacts removed; %s delete errors",
            deleted_files,
            delete_errors,
        )
    return {"artifacts_removed": deleted_files, "delete_errors": delete_errors}


def task_cleanup_search_sessions():
    """
    Delete expired in-memory search pagination sessions.
    """
    from .views import KVSearchView

    removed_count = KVSearchView.cleanup_expired_search_sessions()
    return {"sessions_removed": removed_count}


# INIT of the Program..

# Check if the folder exists and create subfolders if needed
check_json_storage(db.app.config.get("JSON_FOLDER"))

# Connect to the Kvrocks and keep this index for all indexing.
db.app.config["KVROCKS_IDX"] = KVrocksIndexer(
    host=db.app.config.get("KVROCKS_HOST", "localhost"),
    port=db.app.config.get("KVROCKS_PORT", 6666),
    socket_timeout=_get_scheduler_int_config(
        "KVROCKS_SOCKET_TIMEOUT_SECONDS",
        DEFAULT_KVROCKS_SOCKET_TIMEOUT_SECONDS,
    ),
)

# Connect to the Mieili DB ( if the index is not present create IT)
client = meilisearch.Client(
    db.app.config.get("MEILI_DATABASE_URI"),
    db.app.config.get("MEILI_KEY"),
    timeout=_get_scheduler_int_config(
        "MEILI_HTTP_TIMEOUT_SECONDS",
        DEFAULT_MEILI_HTTP_TIMEOUT_SECONDS,
    ),
)

# If the method is online fetch the TLDs.
db.app.config["TLDS"] = []
if db.app.config["ONLINETLD"]:
    # Download https://data.iana.org/TLD/tlds-alpha-by-domain.txt and create an array of TLDs
    db.app.config["TLDS"] = fetch_tlds()
db.app.config["TLDS"] += db.app.config["TLDADD"]  # Append to the list the custom TLDs.

try:
    client.create_index("plum")
except MeilisearchError as error:
    # Meilisearch may be starting/restarting independently.  Keep the web
    # application alive; scheduler tasks will retry their requests later.
    logger.warning("Meilisearch unavailable during startup; deferring index setup: %s", error)
index = client.index("plum")
# Save the client Index to the global config.
db.app.config["MEILI_IDX"] = index
# index.add_documents({"hello": "Word"})

# If the database is new, set the searchable attibute.
try:
    current_attrs = index.get_searchable_attributes()
    if not current_attrs:  # ou current_attrs == ["*"] selon la version
        task = index.update_filterable_attributes(["ip"])
        index.wait_for_task(task.task_uid)
except MeilisearchError as error:
    logger.warning("Deferred Meilisearch index configuration: %s", error)

# Start the scheduled jobs.
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=task_master_of_puppets,
    trigger="interval",
    id="scan_orchestration",
    max_instances=1,
    minutes=db.app.config.get("SCHEDULER_DELAY"),
)
scheduler.add_job(
    func=task_scheduler_maintenance,
    trigger="interval",
    id="scheduler_maintenance",
    max_instances=1,
    minutes=db.app.config.get("SCHEDULER_DELAY"),
)
scheduler.start()


def _shutdown_scheduler():
    """Stop APScheduler before Python tears down its thread pool."""
    if scheduler.running:
        try:
            scheduler.shutdown(wait=False)
            logging.getLogger(__name__).info("Scheduler shut down cleanly")
        except (RuntimeError, SchedulerNotRunningError):
            # Shutdown can race with the process manager during termination.
            pass


atexit.register(_shutdown_scheduler)
