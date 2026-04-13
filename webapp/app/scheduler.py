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
from . import db
from .models import Targets, Jobs, ScanProfiles, TargetScanStates
from .utils.mutils import is_valid_fqdn, fetch_tlds
from .utils.kvrocks import KVrocksIndexer
from .utils.result_parser import parse_json
from .utils.timeutils import utcnow_aware, utcnow_naive, ensure_utc_naive

logger = logging.getLogger("flask_appbuilder")

job = []


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
            "cleanup_jobs": _run_scheduler_step("cleanup_jobs", task_cleanup_jobs),
            "cleanup_export_jobs": _run_scheduler_step(
                "cleanup_export_jobs", task_cleanup_export_jobs
            ),
        }
        total_elapsed = time.perf_counter() - scheduler_started_at
        logger.info(
            "Scheduler TASK: tick complete in %.2fs (create_jobs=%.2fs, export_to_dbs=%.2fs, cleanup_jobs=%.2fs, cleanup_export_jobs=%.2fs)",
            total_elapsed,
            step_durations["create_jobs"],
            step_durations["export_to_dbs"],
            step_durations["cleanup_jobs"],
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


def _resolve_profiles_for_target(target, apply_to_all_profiles):
    """
    Return the effective scan profiles for one target.
    """
    profiles = {profile.id: profile for profile in target.scanprofiles}
    for profile in apply_to_all_profiles:
        profiles.setdefault(profile.id, profile)
    return list(profiles.values())


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
    db.session.execute(
        text(
            """
            UPDATE targets
               SET working = CASE
                   WHEN EXISTS (
                        SELECT 1
                          FROM target_scan_states AS tss
                         WHERE tss.target_id = targets.id
                           AND tss.working = 1
                   ) THEN 1
                   ELSE 0
               END
            """
        )
    )
    db.session.flush()
    return released_states


def task_create_jobs():
    """
    This function will;
        for each non scanned network cidr
            create small jobs of 256 hosts
            set the network in working state

        for each currently scanned cidr
            unset working if no more pending jobs -> Could also be done when job received.

    """
    released_states = _release_orphaned_working_states()
    range_chunks_by_profile = defaultdict(list)
    hostname_chunks_by_profile = defaultdict(list)
    small_ranges_by_profile = defaultdict(list)
    profile_stats = defaultdict(
        lambda: {
            "scheduled_states": 0,
            "range_jobs": 0,
            "host_jobs": 0,
        }
    )
    apply_to_all_profiles = (
        db.session.query(ScanProfiles).filter(ScanProfiles.apply_to_all == True).all()
    )
    state_cache = {
        (state.target_id, state.scanprofile_id): state
        for state in db.session.query(TargetScanStates).all()
    }
    now = utcnow_naive()
    active_targets_processed = 0
    state_created_count = 0
    state_already_working_count = 0
    state_recently_scanned_count = 0
    profiles_without_ports_skipped = 0
    profiles_without_cycle_skipped = 0

    if released_states:
        logger.warning(
            "Create Job TASK: released %s orphan target/profile working states before scheduling",
            released_states,
        )

    for target in db.session.query(Targets).filter(Targets.active == True).yield_per(100):
        active_targets_processed += 1
        target_working = False
        resolved_profiles = _resolve_profiles_for_target(target, apply_to_all_profiles)

        for profile in resolved_profiles:
            state = state_cache.get((target.id, profile.id))
            if state is None:
                state = TargetScanStates(target=target, scanprofile=profile)
                db.session.add(state)
                state_cache[(target.id, profile.id)] = state
                state_created_count += 1

            if state.working:
                target_working = True
                state_already_working_count += 1
                continue

            cycle_minutes = profile.scan_cycle_minutes
            if not cycle_minutes or cycle_minutes <= 0:
                profiles_without_cycle_skipped += 1
                logger.warning(
                    "Skipping profile %s for target %s because scan_cycle_minutes is not set",
                    profile.name,
                    target.value,
                )
                state.working = False
                continue
            last_scan = ensure_utc_naive(state.last_scan)
            if last_scan and last_scan >= now - timedelta(minutes=cycle_minutes):
                state_recently_scanned_count += 1
                continue

            if is_valid_fqdn(target.value):
                hostname_chunks_by_profile[profile.id].append(
                    {"hosts": [target.value], "targets": [target], "states": [state]}
                )
            else:
                net = IPNetwork(target.value)
                if net.size > 256:
                    ips = list(net)
                    for i in range(0, len(ips), 256):
                        block = ips[i : i + 256]
                        range_chunks_by_profile[profile.id].append(
                            {
                                "cidrs": [str(c) for c in cidr_merge(block)],
                                "targets": [target],
                                "states": [state],
                            }
                        )
                else:
                    small_ranges_by_profile[profile.id].append(
                        {"ips": list(net), "target": target, "state": state}
                    )

            state.working = True
            target_working = True
            profile_stats[profile.id]["scheduled_states"] += 1

        target.working = target_working

    for profile_id, small_ranges in small_ranges_by_profile.items():
        current_block = []
        current_targets = {}
        current_states = {}
        for record in sorted(small_ranges, key=lambda x: x["ips"][0]):
            for ip in record["ips"]:
                current_block.append(ip)
                current_targets[record["target"].id] = record["target"]
                current_states[id(record["state"])] = record["state"]
                if len(current_block) == 256:
                    range_chunks_by_profile[profile_id].append(
                        {
                            "cidrs": [str(c) for c in cidr_merge(current_block)],
                            "targets": list(current_targets.values()),
                            "states": list(current_states.values()),
                        }
                    )
                    current_block = []
                    current_targets = {}
                    current_states = {}

        if current_block:
            range_chunks_by_profile[profile_id].append(
                {
                    "cidrs": [str(c) for c in cidr_merge(current_block)],
                    "targets": list(current_targets.values()),
                    "states": list(current_states.values()),
                }
            )

    profile_map = {
        profile.id: profile for profile in db.session.query(ScanProfiles).yield_per(100)
    }

    range_job_count = 0
    for profile_id, chunks in range_chunks_by_profile.items():
        profile = profile_map.get(profile_id)
        if profile is None:
            continue
        scan_ports = _serialize_profile_ports(profile)
        scan_nses = _serialize_profile_nses(profile)
        if not scan_ports:
            logger.warning("Skipping profile %s because it has no ports", profile.name)
            profiles_without_ports_skipped += 1
            for chunk in chunks:
                for state in chunk["states"]:
                    state.working = False
            continue

        for chunk in chunks:
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
            profile_stats[profile_id]["range_jobs"] += 1

    host_job_count = 0
    for profile_id, hostname_chunks in hostname_chunks_by_profile.items():
        profile = profile_map.get(profile_id)
        if profile is None:
            continue
        scan_ports = _serialize_profile_ports(profile)
        scan_nses = _serialize_profile_nses(profile)
        if not scan_ports:
            logger.warning("Skipping profile %s because it has no ports", profile.name)
            profiles_without_ports_skipped += 1
            for chunk in hostname_chunks:
                for state in chunk["states"]:
                    state.working = False
            continue

        for i in range(0, len(hostname_chunks), 256):
            chunk256 = hostname_chunks[i : i + 256]
            new_job = Jobs()
            new_job.uid = str(uuid.uuid4())
            final = []
            targets = {}
            for item in chunk256:
                final.extend(item["hosts"])
                for target in item["targets"]:
                    targets[target.id] = target
            new_job.job = ",".join(final)
            new_job.scanprofile = profile
            new_job.scan_ports = scan_ports
            new_job.scan_nses = scan_nses
            new_job.priority = profile.priority or 0
            for target in targets.values():
                new_job.targets.append(target)
                target.working = True
            db.session.add(new_job)
            host_job_count += 1
            profile_stats[profile_id]["host_jobs"] += 1

    for target in db.session.query(Targets).filter(Targets.active == True).yield_per(100):
        target.working = any(state.working for state in target.scan_states)

    db.session.commit()
    total_jobs_created = range_job_count + host_job_count
    active_profiles_with_jobs = sum(
        1
        for stats in profile_stats.values()
        if stats["range_jobs"] or stats["host_jobs"]
    )
    summary_log = (
        "Create Job TASK: %s jobs created across %s profiles (%s range, %s host); "
        "%s active targets processed; %s target/profile states scheduled; "
        "%s states skipped as already working; %s states skipped as recently scanned; "
        "%s state rows created; %s orphan states released; %s profiles skipped without ports; "
        "%s target/profile evaluations skipped without scan frequency"
    )
    summary_args = (
        total_jobs_created,
        active_profiles_with_jobs,
        range_job_count,
        host_job_count,
        active_targets_processed,
        sum(stats["scheduled_states"] for stats in profile_stats.values()),
        state_already_working_count,
        state_recently_scanned_count,
        state_created_count,
        released_states,
        profiles_without_ports_skipped,
        profiles_without_cycle_skipped,
    )
    if total_jobs_created == 0:
        logger.warning(summary_log, *summary_args)
    else:
        logger.info(summary_log, *summary_args)

    profile_summaries = []
    for profile_id, stats in profile_stats.items():
        total_profile_jobs = stats["range_jobs"] + stats["host_jobs"]
        if total_profile_jobs == 0:
            continue
        profile = profile_map.get(profile_id)
        profile_name = profile.name if profile is not None else str(profile_id)
        profile_summaries.append(
            f"{profile_name}={total_profile_jobs}"
            f"(range:{stats['range_jobs']},host:{stats['host_jobs']},states:{stats['scheduled_states']})"
        )
    if profile_summaries:
        logger.info("Create Job TASK profiles: %s", "; ".join(profile_summaries))


def task_export_to_dbs():
    """
    Export Local Json to external DB
    """
    # Reuse the connections.
    meili_idx = db.app.config.get("MEILI_IDX")
    kvrocks_idx = db.app.config.get("KVROCKS_IDX")

    input_dir = os.path.expanduser(db.app.config.get("JSON_FOLDER"))

    job_snapshots = []
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
                    pending_meili.append(object_to_save)
                    pending_kvrocks.append(
                        parse_json(object_to_save, db.app.config)
                    )
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

    for job_data in (
        db.session.query(Jobs.id, Jobs.uid)
        .filter(
            Jobs.active == False,
            Jobs.exported == True,
            Jobs.finished == True,
            Jobs.job_end <= utcnow_naive() - timedelta(days=job_scavenge),
        )
        .yield_per(100)
    ):
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

        db.session.query(Jobs).filter(Jobs.id == job_data.id).delete(
            synchronize_session=False
        )
        deleted_jobs += 1

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
