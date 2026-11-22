"""Small SQL counters written once when Island accepts a completed job."""

from datetime import timedelta
import ipaddress
from sqlalchemy import func
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from app.models import Jobs, ScanStatBucket


def count_open_ports(report):
    """Count reported open IP/transport/port observations once per job."""
    hosts = report if isinstance(report, list) else [report]
    observed = set()
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ports = host.get("ports") or []
        if not isinstance(ports, list):
            continue
        for port in ports:
            if not isinstance(port, dict):
                continue
            state = port.get("state") or {}
            if isinstance(state, dict) and state.get("state") == "open":
                observed.add(
                    (
                        str(host.get("addr")),
                        str(port.get("protocol", "tcp")),
                        str(port.get("portid")),
                    )
                )
    return len(observed)


def claim_completed_job(session, job, now):
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
                {Jobs.finished: True, Jobs.active: False, Jobs.job_end: now},
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


def increment_completed_counters(session, job, report, now, ports_targeted=None):
    """After a successful claim, upsert immediately before the same commit."""
    if ports_targeted is None:
        ports_targeted = job_targeted_ports(job)
    values = dict(
        bucket_start=now.replace(second=0, microsecond=0),
        scan_tool=job.scan_tool or "nmap",
        jobs_completed=1,
        ports_targeted=ports_targeted or 0,
        open_ports=count_open_ports(report),
        jobs_without_target_count=int(ports_targeted is None),
    )
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


def activity_series(session, now, period="hour", tool="all"):
    """Read bounded SQL aggregates, including empty intervals, in UTC."""
    period = period if period in ("minute", "hour", "day", "month") else "hour"
    tool = tool if tool in ("nmap", "masscan") else "all"
    step, size, pattern = {
        "minute": (timedelta(minutes=1), 60, "%Y-%m-%d %H:%M"),
        "hour": (timedelta(hours=1), 24, "%Y-%m-%d %H:00"),
        "day": (timedelta(days=1), 30, "%Y-%m-%d"),
        "month": (None, 6, "%Y-%m"),
    }[period]
    end = now.replace(second=0, microsecond=0)
    if period != "minute":
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
        start = intervals[0]
    else:
        start = end - step * (size - 1)
        stop = end + step
        intervals = [start + step * i for i in range(size)]
    table = ScanStatBucket
    dialect = session.get_bind().dialect.name
    stamp = (
        func.date_format(table.bucket_start, pattern.replace("%M", "%i"))
        if dialect == "mysql"
        else func.strftime(pattern, table.bucket_start)
    )
    fields = (
        "jobs_completed",
        "ports_targeted",
        "open_ports",
        "jobs_without_target_count",
    )
    query = session.query(
        stamp, *(func.sum(getattr(table, key)) for key in fields)
    ).filter(table.bucket_start >= start, table.bucket_start < stop)
    if tool != "all":
        query = query.filter(table.scan_tool == tool)
    values = {
        row[0]: dict(zip(fields, (int(n or 0) for n in row[1:])))
        for row in query.group_by(stamp).all()
    }
    rows = []
    for interval in intervals:
        label = interval.strftime(pattern)
        rows.append(dict(label=label, **values.get(label, dict.fromkeys(fields, 0))))
    totals = {key: sum(row[key] for row in rows) for key in fields}
    return dict(period=period, tool=tool, rows=list(reversed(rows)), totals=totals)
