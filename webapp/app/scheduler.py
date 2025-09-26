"""
This module manage asynchrone tasks
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from netaddr import IPNetwork, cidr_merge
from . import db
from .models import Targets, Jobs

logger = logging.getLogger("flask_appbuilder")

job = []


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
        logger.debug("Scheduler create Job for %s", chunk)
        new_job.uid = str(uuid.uuid4())
        # Create target range string.
        new_job.job = " ".join(
            str(cidr) for cidr in cidr_merge(chunk.get("cidrs"))
        )  # Convert to Str Ranges
        for target in chunk.get("source_record_ids"):
            obj_target = db.session.query(Targets).filter(Targets.id == target).scalar()
            new_job.targets.append(obj_target)
            obj_target.working = True  # set the Subnet as "Working"
        db.session.add(new_job)
    db.session.commit()


scheduler = BackgroundScheduler()
if len(scheduler.get_jobs()) == 0:
    scheduler.add_job(
        func=task_create_jobs, trigger="interval", max_instances=1, minutes=1
    )
scheduler.start()
