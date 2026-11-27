"""Completed-job counters and sampled ingestion queue history."""

from datetime import timedelta
import ipaddress
from sqlalchemy import func
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from app.models import IngestionStatSample, Jobs, ScanStatBucket
from app.utils.result_parser import is_external_ip

PERIODS = ("minute", "hour", "hour48", "day", "month")
INGESTION_SAMPLE_MINUTES = 5
INGESTION_RETENTION_DAYS = 185


def report_counts(report):
    """Count unique open observations and inputs to the port-document splitter."""
    hosts = report if isinstance(report, list) else [report]
    observed = set()
    documents = 0
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ports = host.get("ports") or []
        if not isinstance(ports, list) or not ports:
            continue
        address = host.get("addr")
        indexable = is_external_ip(address)
        for port in ports:
            if not isinstance(port, dict):
                continue
            port_id = port.get("portid")
            if indexable and str(port_id or "").strip():
                documents += 1
            state = port.get("state") or {}
            if isinstance(state, dict) and state.get("state") == "open":
                observed.add(
                    (
                        str(address),
                        str(port.get("protocol", "tcp")),
                        str(port_id),
                    )
                )
    return len(observed), documents


def count_open_ports(report):
    """Count reported open IP/transport/port observations once per job."""
    return report_counts(report)[0]


def claim_completed_job(session, job, now, document_count):
    """Claim a still-active attempt; the caller commits or rolls back."""
    # Conditional write handles simultaneous submissions as well as retries.
    with session.no_autoflush:
        claimed = (
            session.query(Jobs)
            .filter(
                Jobs.id == job.id,
                Jobs.finished == False,
                Jobs.active == True,
                Jobs.bot_id == job.bot_id,
                Jobs.attempt_uid == job.attempt_uid,
            )
            .update(
                {
                    Jobs.finished: True,
                    Jobs.active: False,
                    Jobs.job_end: now,
                    Jobs.report_document_count: document_count,
                },
                synchronize_session=False,
            )
        )
    return bool(claimed)


def job_targeted_ports(job):
    """Count intended numeric targets from the job snapshot without DNS or I/O."""
    targets = getattr(job, "job", None)
    ports = getattr(job, "scan_ports", None)
    if not targets or not ports:
        return None
    try:
        networks = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in targets.split(",")
        ]
        host_count = sum(
            network.num_addresses
            for family in (4, 6)
            for network in ipaddress.collapse_addresses(
                item for item in networks if item.version == family
            )
        )
        numbers = set()
        for value in ports.split(","):
            bounds = value.strip().split("-")
            if len(bounds) not in (1, 2):
                return None
            start, end = int(bounds[0]), int(bounds[-1])
            if not 1 <= start <= end <= 65535:
                return None
            numbers.update(range(start, end + 1))
    except (ValueError, TypeError, AttributeError):
        return None
    count = host_count * len(numbers)
    return count if count <= 10**12 else None


def increment_completed_counters(session, job, open_ports, now, ports_targeted=None):
    """After a successful claim, upsert immediately before the same commit."""
    if ports_targeted is None:
        ports_targeted = job_targeted_ports(job)
    values = {
        "bucket_start": now.replace(second=0, microsecond=0),
        "scan_tool": job.scan_tool or "nmap",
        "jobs_completed": 1,
        "ports_targeted": ports_targeted or 0,
        "open_ports": open_ports,
        "jobs_without_target_count": int(ports_targeted is None),
    }
    table = ScanStatBucket.__table__
    dialect = session.get_bind().dialect.name
    fields = (
        "jobs_completed",
        "ports_targeted",
        "open_ports",
        "jobs_without_target_count",
    )
    if dialect == "mysql":
        statement = mysql_insert(table).values(**values)
        statement = statement.on_duplicate_key_update(
            **{key: table.c[key] + statement.inserted[key] for key in fields}
        )
    elif dialect == "sqlite":
        statement = sqlite_insert(table).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=[table.c.bucket_start, table.c.scan_tool],
            set_={key: table.c[key] + statement.excluded[key] for key in fields},
        )
    else:
        raise RuntimeError("Scan activity statistics require MySQL or SQLite")
    session.execute(statement)
    return True


def _series_window(now, period, minute_step=1):
    step, size, pattern = {
        "minute": (timedelta(minutes=minute_step), 60 // minute_step, "%Y-%m-%d %H:%M"),
        "hour": (timedelta(hours=1), 24, "%Y-%m-%d %H:00"),
        "hour48": (timedelta(hours=1), 48, "%Y-%m-%d %H:00"),
        "day": (timedelta(days=1), 30, "%Y-%m-%d"),
        "month": (None, 6, "%Y-%m"),
    }[period]
    end = now.replace(second=0, microsecond=0)
    if period == "minute":
        end = end.replace(minute=end.minute - end.minute % minute_step)
    else:
        end = end.replace(minute=0)
    if period == "day":
        end = end.replace(hour=0)
    if period == "month":
        month_index = now.year * 12 + now.month - 1
        boundaries = [
            now.replace(
                year=i // 12,
                month=i % 12 + 1,
                day=1,
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
            for i in range(month_index - 5, month_index + 2)
        ]
        intervals, stop = boundaries[:-1], boundaries[-1]
    else:
        start = end - step * (size - 1)
        stop = end + step
        intervals = [start + step * i for i in range(size)]
    return intervals, stop, pattern


def _bucket_label(session, column, pattern):
    if session.get_bind().dialect.name == "mysql":
        return func.date_format(column, pattern.replace("%M", "%i"))
    return func.strftime(pattern, column)


def activity_series(session, now, period="hour", tool="all"):
    """Read bounded SQL aggregates, including empty intervals, in UTC."""
    period = period if period in PERIODS else "hour"
    tool = tool if tool in ("nmap", "masscan") else "all"
    intervals, stop, pattern = _series_window(now, period)
    table = ScanStatBucket
    stamp = _bucket_label(session, table.bucket_start, pattern)
    fields = (
        "jobs_completed",
        "ports_targeted",
        "open_ports",
        "jobs_without_target_count",
    )
    query = session.query(
        stamp, *(func.sum(getattr(table, key)) for key in fields)
    ).filter(table.bucket_start >= intervals[0], table.bucket_start < stop)
    if tool != "all":
        query = query.filter(table.scan_tool == tool)
    values = {
        row[0]: dict(zip(fields, (int(n or 0) for n in row[1:])))
        for row in query.group_by(stamp).all()
    }
    rows = [
        {"label": label, **values.get(label, dict.fromkeys(fields, 0))}
        for label in (interval.strftime(pattern) for interval in reversed(intervals))
    ]
    totals = {key: sum(row[key] for row in rows) for key in fields}
    return {"period": period, "tool": tool, "rows": rows, "totals": totals}


def sample_ingestion_queue(session, now):
    """Sample a covering SQL index without opening result files or calling Meili."""
    documents = func.coalesce(Jobs.meili_documents_total, Jobs.report_document_count)
    pending, known, count = (
        session.query(func.count(), func.count(documents), func.sum(documents))
        .filter(
            Jobs.active.is_(False), Jobs.finished.is_(True), Jobs.exported.is_(False)
        )
        .one()
    )
    # Release the SQLite read transaction before acquiring the write lock.
    session.rollback()
    sampled_at = now.replace(
        minute=now.minute - now.minute % INGESTION_SAMPLE_MINUTES,
        second=0,
        microsecond=0,
    )
    values = {
        "sampled_at": sampled_at,
        "pending_reports": pending,
        "pending_documents": count or 0,
        "unknown_reports": pending - known,
    }
    table = IngestionStatSample.__table__
    dialect = session.get_bind().dialect.name
    if dialect == "mysql":
        insert = mysql_insert(table).values(**values)
        insert = insert.on_duplicate_key_update(sampled_at=insert.inserted.sampled_at)
    elif dialect == "sqlite":
        insert = sqlite_insert(table).values(**values)
        insert = insert.on_conflict_do_nothing(index_elements=[table.c.sampled_at])
    else:
        raise RuntimeError("Ingestion statistics require MySQL or SQLite")
    session.execute(insert)
    if sampled_at.hour == 0 and sampled_at.minute == 0:
        session.query(IngestionStatSample).filter(
            IngestionStatSample.sampled_at
            < sampled_at - timedelta(days=INGESTION_RETENTION_DAYS)
        ).delete(synchronize_session=False)
    session.commit()


def ingestion_series(session, now, period="hour"):
    """Plot the last sample in each interval because queue depth is a gauge."""
    period = period if period in PERIODS else "hour"
    intervals, stop, pattern = _series_window(now, period, INGESTION_SAMPLE_MINUTES)
    table = IngestionStatSample
    stamp = _bucket_label(session, table.sampled_at, pattern)
    latest_in_bucket = (
        session.query(func.max(table.sampled_at).label("sampled_at"))
        .filter(table.sampled_at >= intervals[0], table.sampled_at < stop)
        .group_by(stamp)
        .subquery()
    )
    samples = {
        sample.sampled_at.strftime(pattern): sample
        for sample in session.query(table).join(
            latest_in_bucket, table.sampled_at == latest_in_bucket.c.sampled_at
        )
    }
    rows = []
    for label in (interval.strftime(pattern) for interval in reversed(intervals)):
        row = {
            "label": label,
            "sampled_at": None,
            "pending_documents": None,
            "pending_reports": None,
            "unknown_reports": 0,
        }
        sample = samples.get(label)
        if sample is not None:
            row.update(
                sampled_at=sample.sampled_at.strftime("%Y-%m-%d %H:%M"),
                pending_reports=sample.pending_reports,
                unknown_reports=sample.unknown_reports,
            )
            if (
                not sample.unknown_reports
                or sample.unknown_reports < sample.pending_reports
            ):
                row["pending_documents"] = sample.pending_documents
        rows.append(row)
    latest = next((row for row in rows if row["sampled_at"] is not None), None)
    return {"rows": rows, "latest": latest}
