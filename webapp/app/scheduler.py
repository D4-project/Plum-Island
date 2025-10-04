"""
This module manage asynchrone tasks
"""

import os
import logging
import shutil
import uuid
import json
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from netaddr import IPNetwork, cidr_merge
import meilisearch
from meilisearch.errors import MeilisearchApiError
from requests.exceptions import HTTPError
from . import db
from .models import Targets, Jobs
from .utils.mutils import is_valid_fqdn

logger = logging.getLogger("flask_appbuilder")

job = []


def task_master_of_puppets():
    """
    Sequentially run Scheduled tasks
    """
    task_create_jobs()  # Create Jobs for the Scanner
    task_export_to_meili()  # Export New Received reports.


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
            logger.debug("%s is not an IP", record.value)
            # small_ranges.append({"ips": record.value, "record_id": record.id})
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
    db.session.commit()


def task_export_to_meili():
    """
    Export Local Json to external DB
    """
    idx = db.app.config.get("MEILI_IDX")

    input_dir = os.path.expanduser(db.app.config.get("JSON_FOLDER"))

    output = []
    success_jobs = []
    # Select "All" Json
    for jobs in (
        db.session.query(Jobs)
        .filter(
            Jobs.active == False,
            Jobs.exported == False,
            Jobs.finished == True,
        )
        .yield_per(100)
    ):

        success_jobs.append(jobs)  # Candidates for a good export
        filepath = os.path.join(input_dir, jobs.uid[0], jobs.uid + ".json")
        print(filepath)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            item = {}
            for item in data:
                # Dns seriously
                ipuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, item.get("sha256")))
                output.append(
                    {
                        "id": ipuid,
                        "ip": item.get("addr"),
                        "body": item,
                    }
                )

    if len(output) > 0:
        try:
            idx.add_documents(output)
            #  if it's success full, we push these result as "exported"
            for success_job in success_jobs:
                success_job.exported = True
                db.session.commit()
        except (MeilisearchApiError, HTTPError):
            # We failed to push to meili.
            db.session.rollback()
            logger.error("Unable to export to Meili database")


# INIT of the Program..

# Check if the folder exists and create subfolders if needed
check_json_storage(db.app.config.get("JSON_FOLDER"))

# Connect to the Mieili DB ( if the index is not present create IT)
client = meilisearch.Client(
    db.app.config.get("MEILI_DATABASE_URI"),
    db.app.config.get("MEILI_KEY"),
)
client.create_index("plum")
index = client.index("plum")
# Save the client Index to the global config.
db.app.config["MEILI_IDX"] = index
index.add_documents({"hello": "Word"})

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
if len(scheduler.get_jobs()) == 0:
    scheduler.add_job(
        func=task_master_of_puppets,
        trigger="interval",
        max_instances=1,
        minutes=db.app.config.get("SCHEDULER_DELAY"),
    )

scheduler.start()
