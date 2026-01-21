"""
This module manage asynchrone tasks
"""

import os
import secrets
import logging
import shutil
import uuid
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from netaddr import IPNetwork, cidr_merge
import meilisearch
from meilisearch.errors import MeilisearchApiError
from requests.exceptions import HTTPError
from . import db
from .models import Targets, Jobs
from .utils.mutils import is_valid_fqdn
from .utils.kvrocks import KVrocksIndexer
from .utils.result_parser import parse_json

logger = logging.getLogger("flask_appbuilder")

job = []


def task_master_of_puppets():
    """
    Sequentially run Scheduled tasks
    """
    task_create_jobs()  # Create Jobs for the Scanner
    task_export_to_dbs()  # Export New Received reports.
    task_cleanup_jobs()  # Delete both Jobs from DB and Files


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


def task_create_jobs():
    """
    This function will;
        for each non scanned network cidr
            create small jobs of 256 hosts
            set the network in working state

        for each currently scanned cidr
            unset working if no more pending jobs -> Could also be done when job received.

    """
    logger.debug("**** Start Create Job TASK ****")

    chunks = []  # Output Jobs
    hostname_chuncks = []  # Output Fqdns
    small_ranges = []

    # HERE need to have a test on the last "scan", > of scan cycle or "empty" -> go create job.
    delay = int(db.app.config.get("SCAN_DELAY"))
    for record in (
        db.session.query(Targets)
        .filter(
            Targets.active == True,
            Targets.working == False,
            (Targets.last_scan == None)
            | (Targets.last_scan < datetime.now(timezone.utc) - timedelta(hours=delay)),
        )
        .yield_per(100)
    ):
        logger.debug("**** Processing Target %s", record.value)
        if is_valid_fqdn(record.value):
            # Traitement si c'est un FQDN
            logger.debug("%s is not an IP, storing fqnd", record.value)
            hostname_chuncks.append(
                {"host": [record.value], "source_record_ids": [record.id]}
            )
        else:
            # Split ranges less than 256 IP or More
            net = IPNetwork(record.value)
            if net.size > 256:
                # Split > 256 Ip Ranges
                ips = list(net)
                for i in range(0, len(ips), 256):
                    block = ips[i : i + 256]
                    chunks.append(
                        {
                            "cidrs": [str(c) for c in cidr_merge(block)],
                            "source_record_ids": [record.id],
                        }
                    )
            else:
                small_ranges.append({"ips": list(net), "record_id": record.id})

    # Make packets of < 256 IPs
    current_block = []
    current_records = set()

    for r in sorted(small_ranges, key=lambda x: x["ips"][0]):
        for ip in r["ips"]:
            current_block.append(ip)
            current_records.add(r["record_id"])
            if len(current_block) == 256:
                chunks.append(
                    {
                        "cidrs": [str(c) for c in cidr_merge(current_block)],
                        "source_record_ids": sorted(current_records),
                    }
                )
                current_block = []
                current_records = set()

    # Feed last packet with remaining ip/ranges.
    if current_block:
        chunks.append(
            {
                "cidrs": [str(c) for c in cidr_merge(current_block)],
                "source_record_ids": sorted(current_records),
            }
        )

    # Now from 256 Ip's Chunks do the Scan Jobs
    for chunk in chunks:
        new_job = Jobs()
        new_job.job = []  # Create the Array of JobTodo
        logger.debug("Scheduler create Job for %s", chunk)
        new_job.uid = str(uuid.uuid4())
        # Create target range string.
        new_job.job = ",".join(
            str(cidr) for cidr in cidr_merge(chunk.get("cidrs"))
        )  # Convert to Str Ranges
        for target in chunk.get("source_record_ids"):
            obj_target = db.session.query(Targets).filter(Targets.id == target).scalar()
            new_job.targets.append(obj_target)
            obj_target.working = True  # set the Subnet as "Working"
        db.session.add(new_job)

    # Now do packets of 256 hosts.
    i = 0
    chunk256 = []
    print(hostname_chuncks)
    for chunck in hostname_chuncks:
        chunk256.append(chunck)
        i += 1
        if i == 256 or i == len(hostname_chuncks):  # si max ou 256 hosts
            i = 0
            new_job = Jobs()
            new_job.job = []  # Create the Array of JobTodo
            logger.debug("Scheduler create Job for %s", chunk256)
            new_job.uid = str(uuid.uuid4())
            # Create target range string.
            final = []
            for item in chunk256:
                for host in item.get("host"):
                    final.append(host)
            new_job.job = ",".join(final)
            print(final)
            for item in chunk256:
                for target in item.get("source_record_ids"):
                    obj_target = (
                        db.session.query(Targets).filter(Targets.id == target).scalar()
                    )
                new_job.targets.append(obj_target)
                obj_target.working = True  # set the Subnet as "Working"
            db.session.add(new_job)
            chunk256 = []
    db.session.commit()
    logger.debug("**** Stop Job TASK SCHEDULER ****")


def task_export_to_dbs():
    """
    Export Local Json to external DB
    """
    logger.debug("**** Start TASK EXPORT ****")
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
        start_index = total_documents
        end_index = total_documents + len(pending_meili) - 1
        logger.debug(
            "Export batch %s (items %s-%s)", batch_count, start_index, end_index
        )
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
            logger.debug("Analysis of %s", filepath)

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
                    pending_kvrocks.append(parse_json(object_to_save))
                    pending_job_refs.append(job["id"])
                    outstanding_docs[job["id"]] += 1

                    if len(pending_meili) >= batch_size:
                        flush_batch()

            completed_jobs.add(job["id"])
            if outstanding_docs[job["id"]] == 0:
                ready_jobs.add(job["id"])

        flush_batch()

        logger.debug(
            "Total exported documents %s across %s batches",
            total_documents,
            batch_count,
        )

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
        else:
            logger.debug("No jobs ready to mark as exported")
    except (MeilisearchApiError, HTTPError):
        db.session.rollback()
        logger.error("Unable to export to Meili database")
    finally:
        db.session.remove()

    logger.debug("**** Stop TASK EXPORT ****")


def task_cleanup_jobs():
    """
    This procedure will delete both Jobs from DB and Files
    """

    job_scavenge = db.app.config.get("JOB_SCAVENGE")
    logger.debug("**** Start Cleanup Job at %s Days****", job_scavenge)

    job_scavenge = db.app.config.get("JOB_SCAVENGE")
    json_folder = os.path.expanduser(db.app.config.get("JSON_FOLDER"))
    deleted_jobs = 0

    for job_data in (
        db.session.query(Jobs.id, Jobs.uid)
        .filter(
            Jobs.active == False,
            Jobs.exported == True,
            Jobs.finished == True,
            Jobs.job_end <= datetime.now(timezone.utc) - timedelta(days=job_scavenge),
        )
        .yield_per(100)
    ):
        logger.debug("Cleanup Scan Data %s", job_data)
        filepath = os.path.join(
            json_folder,
            job_data.uid[0],
            f"{job_data.uid}.json",
        )
        try:
            os.remove(filepath)
            logger.debug("Deleted job file %s", filepath)
        except FileNotFoundError:
            logger.warning("Job file already absent %s", filepath)
        except OSError as err:
            logger.error("Unable to delete job file %s: %s", filepath, err)

        db.session.query(Jobs).filter(Jobs.id == job_data.id).delete(
            synchronize_session=False
        )
        deleted_jobs += 1

    if deleted_jobs:
        db.session.commit()
        logger.debug("Cleanup removed %s jobs", deleted_jobs)
    else:
        logger.debug("No jobs eligible for cleanup")

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
