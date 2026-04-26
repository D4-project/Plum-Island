"""
Helpers for scheduled Markdown reports.
"""

import calendar
import ipaddress
import re
import smtplib
from collections import Counter
from datetime import datetime, timezone
from email.message import EmailMessage

from .timeutils import ensure_utc_naive, utcnow_naive


EMAIL_SPLIT_RE = re.compile(r"[\n,;]+")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MONTHLY = "monthly"


def normalize_report_emails(emails_value):
    """
    Normalize report email text to a unique lowercase list.
    """
    values = []
    seen = set()
    for part in EMAIL_SPLIT_RE.split(str(emails_value or "")):
        email = part.strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        values.append(email)
    return values


def format_report_emails(emails_value):
    """
    Serialize report emails to the editable newline-separated DB format.
    """
    return "\n".join(normalize_report_emails(emails_value))


def validate_report_emails(emails_value):
    """
    Return normalized report emails or raise ValueError.
    """
    emails = normalize_report_emails(emails_value)
    if not emails:
        raise ValueError("At least one reporting email is required")
    invalid = [email for email in emails if not EMAIL_RE.match(email)]
    if invalid:
        raise ValueError(f"Invalid reporting email: {invalid[0]}")
    return emails


def normalize_report_fields(report):
    """
    Normalize and validate one report model instance.
    """
    report.name = str(report.name or "").strip()
    if not report.name:
        raise ValueError("Report name is required")

    report.description = str(report.description or "").strip()
    report.query = str(report.query or "").strip()
    if not report.query:
        raise ValueError("Report query is required")

    report.emails = "\n".join(validate_report_emails(report.emails))
    report.schedule_type = str(report.schedule_type or MONTHLY).strip().lower()
    if report.schedule_type != MONTHLY:
        raise ValueError("Only monthly report scheduling is supported")

    report.schedule_day = int(report.schedule_day or 1)
    if report.schedule_day < 1 or report.schedule_day > 28:
        raise ValueError("Report schedule day must be between 1 and 28")

    report.schedule_hour = int(report.schedule_hour or 0)
    if report.schedule_hour < 0 or report.schedule_hour > 23:
        raise ValueError("Report schedule hour must be between 0 and 23")

    return report


def _add_months(date_value, months):
    """
    Add calendar months while clamping the day to the destination month.
    """
    month_index = date_value.month - 1 + months
    year = date_value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(date_value.day, calendar.monthrange(year, month)[1])
    return date_value.replace(year=year, month=month, day=day)


def _subtract_one_month(date_value):
    return _add_months(date_value, -1)


def compute_next_report_run(report, now=None):
    """
    Compute the next automatic run time for one report.
    """
    now = ensure_utc_naive(now) or utcnow_naive()
    schedule_day = max(1, min(int(report.schedule_day or 1), 28))
    schedule_hour = max(0, min(int(report.schedule_hour or 0), 23))
    candidate = now.replace(
        day=schedule_day,
        hour=schedule_hour,
        minute=0,
        second=0,
        microsecond=0,
    )
    if candidate <= now:
        candidate = _add_months(candidate, 1)
    return candidate


def compute_report_interval(report, run_at=None):
    """
    Return the temporal search interval for a report run.

    Monthly reports search since their last real run. Before the first run,
    the interval defaults to one calendar month before the run time.
    """
    run_at = ensure_utc_naive(run_at) or utcnow_naive()
    last_run_at = ensure_utc_naive(getattr(report, "last_run_at", None))
    if last_run_at is None or last_run_at >= run_at:
        last_run_at = _subtract_one_month(run_at)
    return last_run_at, run_at


def compute_previous_report_interval(report, from_dt, to_dt):
    """
    Return the previous comparable report interval.
    """
    _ = to_dt
    if str(getattr(report, "schedule_type", "") or "").lower() != MONTHLY:
        return None, None

    from_dt = ensure_utc_naive(from_dt)
    if from_dt is None:
        return None, None
    return _subtract_one_month(from_dt), from_dt


def datetime_to_epoch(value):
    """
    Convert a naive UTC datetime to an epoch-second timestamp.
    """
    value = ensure_utc_naive(value)
    if value is None:
        return None
    return int(value.replace(tzinfo=timezone.utc).timestamp())


def _format_datetime(value):
    value = ensure_utc_naive(value)
    if value is None:
        return "N/A"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _port_sort_key(port):
    try:
        return (0, int(port))
    except (TypeError, ValueError):
        return (1, str(port))


def _ip_sort_key(ip):
    """
    Sort IPs numerically, falling back to text for unexpected values.
    """
    try:
        parsed_ip = ipaddress.ip_address(str(ip))
        return (parsed_ip.version, int(parsed_ip), "")
    except ValueError:
        return (99, 0, str(ip))


def collect_report_ports(indexer, results):
    """
    Collect per-IP open ports and global host counts from Kvrocks port indexes.
    """
    per_ip_ports = {}
    port_counter = Counter()
    for ip, uids in (results or {}).items():
        ip_ports = set()
        pipe = indexer.r.pipeline(transaction=False)
        for uid in uids:
            pipe.smembers(f"ports:{uid}")
        for ports in pipe.execute():
            for port in ports or []:
                port_value = str(port).strip()
                if port_value:
                    ip_ports.add(port_value)

        sorted_ports = sorted(ip_ports, key=_port_sort_key)
        per_ip_ports[ip] = sorted_ports
        port_counter.update(sorted_ports)

    return per_ip_ports, port_counter


def collect_report_tags(indexer, results):
    """
    Collect per-IP tags from Kvrocks tag indexes.
    """
    per_ip_tags = {}
    for ip, uids in (results or {}).items():
        ip_tags = set()
        pipe = indexer.r.pipeline(transaction=False)
        for uid in uids:
            pipe.smembers(f"tags:{uid}")
        for tags in pipe.execute():
            for tag in tags or []:
                tag_value = str(tag).strip()
                if tag_value:
                    ip_tags.add(tag_value)
        per_ip_tags[ip] = sorted(ip_tags, key=str.lower)
    return per_ip_tags


def compute_new_open_ports(per_ip_ports, previous_per_ip_ports):
    """
    Return ports present in the current interval but absent in the previous one.
    """
    new_open_ports = {}
    for ip, ports in (per_ip_ports or {}).items():
        previous_ports = set(previous_per_ip_ports.get(ip, []))
        new_ports = sorted(
            {str(port) for port in ports or [] if str(port) not in previous_ports},
            key=_port_sort_key,
        )
        if new_ports:
            new_open_ports[ip] = new_ports
    return new_open_ports


def build_report_markdown(
    report,
    search_results,
    per_ip_ports,
    port_counter,
    from_dt,
    to_dt,
    per_ip_tags=None,
    new_open_ports=None,
):
    """
    Render one report as Markdown.
    """
    results = search_results.get("results") or {}
    total_ips = len(results)
    total_scans = sum(len(uids) for uids in results.values())

    lines = [
        f"# {report.name}",
        "",
    ]
    if report.description:
        lines.extend([report.description, ""])

    lines.extend(
        [
            "## Summary",
            "",
            f"- Query: `{report.query}`",
            f"- Period: {_format_datetime(from_dt)} to {_format_datetime(to_dt)}",
            f"- Matching IPs: {total_ips}",
            f"- Matching scans: {total_scans}",
            "",
            "## Open Ports",
            "",
        ]
    )

    if port_counter:
        for port, count in sorted(
            port_counter.items(),
            key=lambda item: (-item[1], _port_sort_key(item[0])),
        ):
            lines.append(f"- {port}: {count} host{'s' if count != 1 else ''}")
    else:
        lines.append("- No indexed open ports found.")

    if str(getattr(report, "schedule_type", "") or "").lower() == MONTHLY:
        lines.extend(["", "## New opened port", ""])
        if new_open_ports:
            for ip in sorted(new_open_ports, key=_ip_sort_key):
                lines.extend(
                    [
                        f"- {ip}",
                        f"  - New ports: {', '.join(new_open_ports[ip])}",
                    ]
                )
        else:
            lines.append("- No newly opened ports detected.")

    lines.extend(["", "## Hosts", ""])
    if not results:
        lines.append("No matching hosts.")
    else:
        for ip in sorted(results, key=_ip_sort_key):
            tags = per_ip_tags.get(ip, []) if per_ip_tags else []
            ports = per_ip_ports.get(ip) or []
            ports_text = ", ".join(ports) if ports else "none"
            lines.extend(
                [
                    f"- {ip}",
                ]
            )
            if tags:
                lines.append(f"  - Tag: {', '.join(tags)}")
            lines.extend(
                [
                    f"  - Open ports: {ports_text}",
                    f"  - Scan results: {len(results[ip])}",
                ]
            )

    lines.extend(
        [
            "",
            "## Disclaimer",
            "",
            (
                "This report is provided as-is. Results may be incomplete due to "
                "unscanned ports, transient scan errors, unavailable services, "
                "or other collection limitations."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def send_report_markdown(app_config, report, markdown_body):
    """
    Send one Markdown report through the configured SMTP relay.
    """
    smtp_host = str(app_config.get("REPORT_SMTP_HOST", "") or "").strip()
    if not smtp_host:
        raise ValueError("REPORT_SMTP_HOST is not configured")

    smtp_port = int(app_config.get("REPORT_SMTP_PORT", 25) or 25)
    smtp_user = str(app_config.get("REPORT_SMTP_USER", "") or "").strip()
    smtp_password = str(app_config.get("REPORT_SMTP_PASSWORD", "") or "")
    smtp_from = (
        str(app_config.get("REPORT_SMTP_FROM", "") or "").strip()
        or smtp_user
        or "plum-reports@localhost"
    )
    use_ssl = bool(app_config.get("REPORT_SMTP_USE_SSL", False))
    use_tls = bool(app_config.get("REPORT_SMTP_USE_TLS", False))

    recipients = report.emails_list()
    if not recipients:
        raise ValueError("Report has no recipients")

    message = EmailMessage()
    message["Subject"] = f"P.L.U.M. report: {report.name}"
    message["From"] = smtp_from
    message["To"] = ", ".join(recipients)
    message.set_content(markdown_body)

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with smtp_class(smtp_host, smtp_port, timeout=30) as smtp:
        if use_tls and not use_ssl:
            smtp.starttls()
        if smtp_user:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)
