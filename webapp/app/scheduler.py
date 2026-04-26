"""
This module manage asynchrone tasks
"""

import os
import secrets
import logging
import shutil
import uuid
import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from netaddr import IPNetwork, cidr_merge
import meilisearch
from meilisearch.errors import MeilisearchApiError
from requests.exceptions import HTTPError
from sqlalchemy import text
from sqlalchemy.orm import joinedload
from . import db
from .models import Targets, Jobs, ScanProfiles, TargetScanStates, assoc_jobs_targets
from .models import Reports
from .models import TagRules
from .utils.mutils import is_valid_fqdn, fetch_tlds
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

logger = logging.getLogger("flask_appbuilder")

job = []
DEFAULT_QUEUE_TARGET_JOBS_PER_PROFILE = 256
DEFAULT_QUEUE_STATE_BATCH_SIZE = 128
DEFAULT_STATE_SYNC_BATCH_SIZE = 2048
DEFAULT_MAX_NEW_JOBS_PER_TICK = 1024
DEFAULT_ORPHAN_SWEEP_INTERVAL_SECONDS = 900


def _run_scheduler_step(step_label, step_func):
    """
    Log start/end timing for one scheduler step.
    """
    started_at = time.perf_counter()
    logger.info("Scheduler TASK: starting %s", step_label)
    step_func()
    elapsed = time.perf_counter() - started_at
    logger.info("Scheduler TASK: finished %s in %.2fs", step_label, elapsed)
    return elapsed


def task_master_of_puppets():
    """
    Sequentially run Scheduled tasks
    """
    # External migration scripts and manual SQL maintenance can modify the
    # sqlite database outside this process. Start each tick from a fresh ORM
    # session so scheduler decisions use the current persisted state.
    scheduler_started_at = time.perf_counter()
    logger.info("Scheduler TASK: tick start")
    db.session.remove()
    try:
        step_durations = {
            "create_jobs": _run_scheduler_step("create_jobs", task_create_jobs),
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
        total_elapsed = time.perf_counter() - scheduler_started_at
        logger.info(
            "Scheduler TASK: tick complete in %.2fs (create_jobs=%.2fs, export_to_dbs=%.2fs, reports=%.2fs, cleanup_jobs=%.2fs, cleanup_search_sessions=%.2fs, cleanup_export_jobs=%.2fs)",
            total_elapsed,
            step_durations["create_jobs"],
            step_durations["export_to_dbs"],
            step_durations["reports"],
            step_durations["cleanup_jobs"],
            step_durations["cleanup_search_sessions"],
            step_durations["cleanup_export_jobs"],
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


def _release_orphaned_working_states():
    """
    Release target/profile states stuck in working mode without unfinished jobs.
    """
    released_states = db.session.execute(
        text(
            """
            UPDATE target_scan_states
               SET working = 0
             WHERE working = 1
               AND NOT EXISTS (
                    SELECT 1
                      FROM jobs_targets_assoc AS jta
                      JOIN jobs AS j ON j.id = jta.job_id
                     WHERE jta.target_id = target_scan_states.target_id
                       AND j.scanprofile_id = target_scan_states.scanprofile_id
                       AND j.finished = 0
               )
            """
        )
    ).rowcount or 0
    if released_states:
        db.session.execute(
            text(
                """
                UPDATE targets
                   SET working = 0
                 WHERE working = 1
                   AND NOT EXISTS (
                        SELECT 1
                          FROM target_scan_states AS tss
                         WHERE tss.target_id = targets.id
                           AND tss.working = 1
                   )
                """
            )
        )
        db.session.commit()
    return released_states


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


def _sync_missing_scan_states():
    """
    Seed missing target/profile runtime rows in bounded batches.
    """
    batch_limit = _get_scheduler_int_config(
        "SCHEDULER_STATE_SYNC_BATCH_SIZE",
        DEFAULT_STATE_SYNC_BATCH_SIZE,
    )
    inserted_states = 0

    explicit_inserted = (
        db.session.execute(
            text(
                """
                INSERT OR IGNORE INTO target_scan_states (target_id, scanprofile_id, working)
                SELECT spta.target_id, spta.scanprofile_id, 0
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
                """
            ),
            {"limit": batch_limit},
        ).rowcount
        or 0
    )
    inserted_states += explicit_inserted
    remaining = batch_limit - explicit_inserted

    if remaining > 0:
        apply_all_profiles = (
            db.session.query(ScanProfiles.id)
            .filter(ScanProfiles.apply_to_all == True)
            .order_by(ScanProfiles.priority.desc(), ScanProfiles.id.asc())
            .all()
        )
        for row in apply_all_profiles:
            profile_id = row[0]
            if remaining <= 0:
                break
            created_for_profile = (
                db.session.execute(
                    text(
                        """
                        INSERT OR IGNORE INTO target_scan_states (target_id, scanprofile_id, working)
                        SELECT t.id, :profile_id, 0
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
                        """
                    ),
                    {"profile_id": profile_id, "limit": remaining},
                ).rowcount
                or 0
            )
            inserted_states += created_for_profile
            remaining -= created_for_profile

    if inserted_states:
        db.session.commit()
    return inserted_states


def _get_waiting_job_counts_by_profile():
    """
    Return queued job counts keyed by scanprofile id.
    """
    waiting_counts = defaultdict(int)
    rows = db.session.execute(
        text(
            """
            SELECT scanprofile_id, COUNT(*) AS waiting_jobs
              FROM jobs
             WHERE active = 0
               AND finished = 0
               AND scanprofile_id IS NOT NULL
             GROUP BY scanprofile_id
            """
        )
    ).fetchall()
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
            if profile.id > cursor_profile_id:
                start_index = index
                break
        else:
            start_index = 0

    if start_index == 0:
        return profiles
    return profiles[start_index:] + profiles[:start_index]


def _load_due_states_for_profile(profile, now_utc, state_limit):
    """
    Load due target/profile states for one profile, oldest first.
    """
    cutoff = now_utc - timedelta(minutes=profile.scan_cycle_minutes)
    due_state_ids_sql = """
        SELECT tss.id
          FROM target_scan_states AS tss
          JOIN targets AS t
            ON t.id = tss.target_id
         WHERE tss.scanprofile_id = :profile_id
           AND t.active = 1
           AND tss.working = 0
           AND (tss.last_scan IS NULL OR tss.last_scan <= :cutoff)
    """
    if not profile.apply_to_all:
        due_state_ids_sql += """
           AND EXISTS (
                SELECT 1
                  FROM scanprofiles_targets_assoc AS spta
                 WHERE spta.scanprofile_id = tss.scanprofile_id
                   AND spta.target_id = tss.target_id
           )
        """
    due_state_ids_sql += """
         ORDER BY CASE WHEN tss.last_scan IS NULL THEN 0 ELSE 1 END ASC,
                  tss.last_scan ASC,
                  tss.target_id ASC
         LIMIT :limit
    """

    state_ids = [
        row[0]
        for row in db.session.execute(
            text(due_state_ids_sql),
            {"profile_id": profile.id, "cutoff": cutoff, "limit": state_limit},
        ).fetchall()
    ]
    if not state_ids:
        return []

    states = (
        db.session.query(TargetScanStates)
        .options(joinedload(TargetScanStates.target))
        .filter(TargetScanStates.id.in_(state_ids))
        .all()
    )
    states_by_id = {state.id: state for state in states}
    return [states_by_id[state_id] for state_id in state_ids if state_id in states_by_id]


def _append_large_network_chunks(target, state, range_chunks):
    """
    Split large networks into /24-sized job chunks without materializing the whole network.
    """
    current_block = []
    for ip in IPNetwork(target.value):
        current_block.append(ip)
        if len(current_block) == 256:
            range_chunks.append(
                {
                    "cidrs": [str(cidr) for cidr in cidr_merge(current_block)],
                    "targets": [target],
                    "states": [state],
                }
            )
            current_block = []
    if current_block:
        range_chunks.append(
            {
                "cidrs": [str(cidr) for cidr in cidr_merge(current_block)],
                "targets": [target],
                "states": [state],
            }
        )


def _merge_small_ranges_into_chunks(small_ranges, range_chunks):
    """
    Merge small IP ranges across states into 256-IP jobs.
    """
    current_block = []
    current_targets = {}
    current_states = {}

    for record in sorted(small_ranges, key=lambda item: item["ips"][0]):
        for ip in record["ips"]:
            current_block.append(ip)
            current_targets[record["target"].id] = record["target"]
            current_states[id(record["state"])] = record["state"]
            if len(current_block) == 256:
                range_chunks.append(
                    {
                        "cidrs": [str(cidr) for cidr in cidr_merge(current_block)],
                        "targets": list(current_targets.values()),
                        "states": list(current_states.values()),
                    }
                )
                current_block = []
                current_targets = {}
                current_states = {}

    if current_block:
        range_chunks.append(
            {
                "cidrs": [str(cidr) for cidr in cidr_merge(current_block)],
                "targets": list(current_targets.values()),
                "states": list(current_states.values()),
            }
        )


def _stage_jobs_for_profile(profile, due_states, scan_ports, scan_nses):
    """
    Convert due states into queued jobs for one profile.
    """
    range_chunks = []
    hostname_chunks = []
    small_ranges = []

    for state in due_states:
        target = state.target
        if target is None:
            continue
        if is_valid_fqdn(target.value):
            hostname_chunks.append(
                {"hosts": [target.value], "targets": [target], "states": [state]}
            )
        else:
            net = IPNetwork(target.value)
            if net.size > 256:
                _append_large_network_chunks(target, state, range_chunks)
            else:
                small_ranges.append({"ips": list(net), "target": target, "state": state})

        state.working = True
        target.working = True

    if small_ranges:
        _merge_small_ranges_into_chunks(small_ranges, range_chunks)

    range_job_count = 0
    for chunk in range_chunks:
        new_job = Jobs()
        new_job.uid = str(uuid.uuid4())
        new_job.job = ",".join(str(cidr) for cidr in cidr_merge(chunk["cidrs"]))
        new_job.scanprofile = profile
        new_job.scan_ports = scan_ports
        new_job.scan_nses = scan_nses
        new_job.priority = profile.priority or 0
        for target in chunk["targets"]:
            new_job.targets.append(target)
            target.working = True
        db.session.add(new_job)
        range_job_count += 1

    host_job_count = 0
    for i in range(0, len(hostname_chunks), 256):
        chunk256 = hostname_chunks[i : i + 256]
        new_job = Jobs()
        new_job.uid = str(uuid.uuid4())
        final_hosts = []
        targets = {}
        for item in chunk256:
            final_hosts.extend(item["hosts"])
            for target in item["targets"]:
                targets[target.id] = target
        new_job.job = ",".join(final_hosts)
        new_job.scanprofile = profile
        new_job.scan_ports = scan_ports
        new_job.scan_nses = scan_nses
        new_job.priority = profile.priority or 0
        for target in targets.values():
            new_job.targets.append(target)
            target.working = True
        db.session.add(new_job)
        host_job_count += 1

    return {
        "scheduled_states": len(due_states),
        "range_jobs": range_job_count,
        "host_jobs": host_job_count,
    }


def task_create_jobs():
    """
    Keep per-profile waiting queues filled without sweeping the whole target set.
    """
    started_at = time.perf_counter()
    released_states = 0
    seeded_states = 0

    orphan_started = time.perf_counter()
    if _should_run_orphan_state_release():
        released_states = _release_orphaned_working_states()
        logger.debug(
            "Create Job TASK debug: orphan-state release completed in %.2fs (released_states=%s)",
            time.perf_counter() - orphan_started,
            released_states,
        )
    else:
        logger.debug(
            "Create Job TASK debug: orphan-state release skipped (cooldown active)"
        )

    sync_started = time.perf_counter()
    seeded_states = _sync_missing_scan_states()
    logger.debug(
        "Create Job TASK debug: state sync completed in %.2fs (seeded_states=%s)",
        time.perf_counter() - sync_started,
        seeded_states,
    )

    queue_target = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_TARGET_JOBS_PER_PROFILE",
        DEFAULT_QUEUE_TARGET_JOBS_PER_PROFILE,
    )
    state_batch_size = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_STATE_BATCH_SIZE",
        DEFAULT_QUEUE_STATE_BATCH_SIZE,
    )
    max_new_jobs_per_tick = _get_scheduler_int_config(
        "SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK",
        DEFAULT_MAX_NEW_JOBS_PER_TICK,
    )

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
    profiles = _rotate_profiles_for_tick(profiles)

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
    profile_summaries = []
    last_processed_profile_id = 0

    fill_started = time.perf_counter()
    for profile in profiles:
        last_processed_profile_id = profile.id
        scan_ports = _serialize_profile_ports(profile)
        if not scan_ports:
            profiles_without_ports += 1
            logger.warning("Create Job TASK: skipping profile %s because it has no ports", profile.name)
            continue

        cycle_minutes = profile.scan_cycle_minutes
        if not cycle_minutes or cycle_minutes <= 0:
            profiles_without_cycle += 1
            logger.warning(
                "Create Job TASK: skipping profile %s because scan_cycle_minutes is not set",
                profile.name,
            )
            continue

        waiting_before = waiting_counts.get(profile.id, 0)
        queue_deficit = queue_target - waiting_before
        if queue_deficit <= 0:
            profiles_already_full += 1
            continue

        state_limit = max(1, min(state_batch_size, queue_deficit))
        due_started = time.perf_counter()
        due_states = _load_due_states_for_profile(profile, now, state_limit)
        due_elapsed = time.perf_counter() - due_started
        if not due_states:
            profiles_without_due_states += 1
            logger.debug(
                "Create Job TASK debug: profile %s has no due states (waiting=%s, deficit=%s, load=%.2fs)",
                profile.name,
                waiting_before,
                queue_deficit,
                due_elapsed,
            )
            continue

        stage_started = time.perf_counter()
        job_counts = _stage_jobs_for_profile(
            profile,
            due_states,
            scan_ports,
            _serialize_profile_nses(profile),
        )
        stage_elapsed = time.perf_counter() - stage_started

        commit_started = time.perf_counter()
        db.session.commit()
        commit_elapsed = time.perf_counter() - commit_started

        new_jobs = job_counts["range_jobs"] + job_counts["host_jobs"]
        waiting_counts[profile.id] = waiting_before + new_jobs
        totals["scheduled_states"] += job_counts["scheduled_states"]
        totals["range_jobs"] += job_counts["range_jobs"]
        totals["host_jobs"] += job_counts["host_jobs"]

        if new_jobs > 0:
            profiles_with_jobs += 1
            profile_summaries.append(
                f"{profile.name}={new_jobs}"
                f"(range:{job_counts['range_jobs']},host:{job_counts['host_jobs']},states:{job_counts['scheduled_states']},queued:{waiting_counts[profile.id]})"
            )

        logger.debug(
            "Create Job TASK debug: profile %s filled in %.2fs (due_load=%.2fs, stage=%.2fs, commit=%.2fs, states=%s, new_jobs=%s, waiting_before=%s, waiting_after=%s)",
            profile.name,
            due_elapsed + stage_elapsed + commit_elapsed,
            due_elapsed,
            stage_elapsed,
            commit_elapsed,
            job_counts["scheduled_states"],
            new_jobs,
            waiting_before,
            waiting_counts[profile.id],
        )

        if totals["range_jobs"] + totals["host_jobs"] >= max_new_jobs_per_tick:
            budget_exhausted = True
            break

    logger.debug(
        "Create Job TASK debug: queue fill completed in %.2fs",
        time.perf_counter() - fill_started,
    )
    if last_processed_profile_id:
        db.app.config["scheduler_profile_cursor_id"] = last_processed_profile_id

    total_jobs_created = totals["range_jobs"] + totals["host_jobs"]
    summary_log = (
        "Create Job TASK: %s jobs created across %s profiles (%s range, %s host); "
        "%s target/profile states scheduled; queue_target=%s; state_batch=%s; "
        "%s state rows seeded; %s orphan states released; %s profiles already full; "
        "%s profiles had no due states; %s profiles skipped without ports; "
        "%s profiles skipped without scan frequency; budget_exhausted=%s"
    )
    summary_args = (
        total_jobs_created,
        profiles_with_jobs,
        totals["range_jobs"],
        totals["host_jobs"],
        totals["scheduled_states"],
        queue_target,
        state_batch_size,
        seeded_states,
        released_states,
        profiles_already_full,
        profiles_without_due_states,
        profiles_without_ports,
        profiles_without_cycle,
        budget_exhausted,
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


def task_export_to_dbs():
    """
    Export Local Json to external DB
    """
    # Reuse the connections.
    meili_idx = db.app.config.get("MEILI_IDX")
    kvrocks_idx = db.app.config.get("KVROCKS_IDX")

    input_dir = os.path.expanduser(db.app.config.get("JSON_FOLDER"))

    job_snapshots = []
    active_tag_rules = compile_tag_rule_records(
        db.session.query(TagRules).filter(TagRules.active == True).all()
    )
    # Select "All" Json
    for job_data in (
        db.session.query(Jobs.id, Jobs.uid)
        .filter(
            Jobs.active == False,
            Jobs.exported == False,
            Jobs.finished == True,
        )
        .yield_per(100)
    ):
        job_snapshots.append({"id": job_data.id, "uid": job_data.uid})

    if not job_snapshots:
        db.session.remove()
        return

    # Release the read transaction before spending time on IO/exports to avoid long locks.
    db.session.commit()
    db.session.remove()

    batch_size = 2500  # How many Document we flush at once to backend.
    pending_meili = []
    pending_kvrocks = []
    pending_job_refs = []
    outstanding_docs = defaultdict(int)
    completed_jobs = set()
    ready_jobs = set()
    total_documents = 0
    batch_count = 0

    def flush_batch():
        """
        This subprocedure flush reports (per IP)
        """
        nonlocal batch_count, total_documents
        if not pending_meili:
            return
        batch_count += 1
        meili_idx.add_documents(pending_meili)
        kvrocks_idx.add_documents_batch(pending_kvrocks)
        for job_id in pending_job_refs:
            outstanding_docs[job_id] -= 1
            if outstanding_docs[job_id] == 0 and job_id in completed_jobs:
                ready_jobs.add(job_id)
        total_documents += len(pending_meili)
        pending_meili.clear()
        pending_kvrocks.clear()
        pending_job_refs.clear()

    try:
        for job in job_snapshots:
            filepath = os.path.join(input_dir, job["uid"][0], job["uid"] + ".json")

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                item = {}
                for item in data:
                    ipuid = str(
                        uuid.uuid5(
                            uuid.NAMESPACE_DNS, item.get("hsh256", secrets.randbits(64))
                        )
                    )
                    object_to_save = {
                        "id": ipuid,
                        "ip": item.get("addr"),
                        "body": item,
                    }
                    parsed_doc = parse_json(
                        object_to_save,
                        db.app.config,
                        tag_rules=active_tag_rules,
                    )
                    pending_meili.append(object_to_save)
                    pending_kvrocks.append(parsed_doc)
                    pending_job_refs.append(job["id"])
                    outstanding_docs[job["id"]] += 1

                    if len(pending_meili) >= batch_size:
                        flush_batch()

            completed_jobs.add(job["id"])
            if outstanding_docs[job["id"]] == 0:
                ready_jobs.add(job["id"])

        flush_batch()
        updated_rows = 0

        if ready_jobs:
            updated_rows = (
                db.session.query(Jobs)
                .filter(
                    Jobs.id.in_(ready_jobs),
                    Jobs.active == False,
                    Jobs.finished == True,
                    Jobs.exported == False,
                )
                .update({Jobs.exported: True}, synchronize_session=False)
            )
            if updated_rows != len(ready_jobs):
                logger.warning(
                    "Exported job mismatch, expected %s updated %s",
                    len(ready_jobs),
                    updated_rows,
                )
            db.session.commit()
        logger.info(
            "Export TASK: %s jobs scanned, %s documents exported in %s batches, %s jobs marked exported",
            len(job_snapshots),
            total_documents,
            batch_count,
            updated_rows,
        )
    except (MeilisearchApiError, HTTPError):
        db.session.rollback()
        logger.error("Unable to export to Meili database")
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
        return

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
        return

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
        db.session.query(Jobs.id, Jobs.uid)
        .filter(
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


def task_cleanup_search_sessions():
    """
    Delete expired in-memory search pagination sessions.
    """
    from .views import KVSearchView

    KVSearchView.cleanup_expired_search_sessions()


# INIT of the Program..

# Check if the folder exists and create subfolders if needed
check_json_storage(db.app.config.get("JSON_FOLDER"))

# Connect to the Kvrocks and keep this index for all indexing.
db.app.config["KVROCKS_IDX"] = KVrocksIndexer(
    db.app.config.get("KVROCKS_HOST", db.app.config.get("KVROCKS_PORT"))
)

# Connect to the Mieili DB ( if the index is not present create IT)
client = meilisearch.Client(
    db.app.config.get("MEILI_DATABASE_URI"),
    db.app.config.get("MEILI_KEY"),
)

# If the method is online fetch the TLDs.
db.app.config["TLDS"] = []
if db.app.config["ONLINETLD"]:
    # Download https://data.iana.org/TLD/tlds-alpha-by-domain.txt and create an array of TLDs
    db.app.config["TLDS"] = fetch_tlds()
db.app.config["TLDS"] += db.app.config["TLDADD"]  # Append to the list the custom TLDs.

client.create_index("plum")
index = client.index("plum")
# Save the client Index to the global config.
db.app.config["MEILI_IDX"] = index
# index.add_documents({"hello": "Word"})

# If the database is new, set the searchable attibute.
current_attrs = index.get_searchable_attributes()
try:
    if not current_attrs:  # ou current_attrs == ["*"] selon la version
        # Declare filterable fields
        task = index.update_filterable_attributes(["ip"])
        index.wait_for_task(task.task_uid)
        # Wait the indexation
except MeilisearchApiError:
    task = index.update_filterable_attributes(["ip"])
    index.wait_for_task(task.task_uid)

# Start the scheduled jobs.
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=task_master_of_puppets,
    trigger="interval",
    max_instances=1,
    minutes=db.app.config.get("SCHEDULER_DELAY"),
)
scheduler.start()
