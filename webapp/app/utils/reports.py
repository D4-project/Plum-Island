"""
Helpers for scheduled Markdown reports.
"""

import calendar
import ipaddress
import json
import logging
import re
import smtplib
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import requests

from .timeutils import ensure_utc_naive, utcnow_naive

logger = logging.getLogger("flask_appbuilder")
EMAIL_SPLIT_RE = re.compile(r"[\n,;]+")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MONTHLY = "monthly"
WEEKLY = "weekly"
REPORT_SCHEDULE_TYPES = frozenset((MONTHLY, WEEKLY))
REPORT_FQDN_LIMIT = 25
REPORT_WEB_PROTOCOL_TAGS = frozenset(("proto:http", "proto:https"))
REPORT_MAIL_PROTOCOL_TAGS = frozenset(("proto:smtp", "proto:imap", "proto:pop3"))


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
    if report.schedule_type not in REPORT_SCHEDULE_TYPES:
        raise ValueError("Report schedule type must be monthly or weekly")

    report.schedule_day = int(report.schedule_day or 1)
    max_schedule_day = 28 if report.schedule_type == MONTHLY else 7
    if report.schedule_day < 1 or report.schedule_day > max_schedule_day:
        if report.schedule_type == MONTHLY:
            raise ValueError("Monthly report day must be between 1 and 28")
        raise ValueError("Weekly report day must be between 1 (Monday) and 7 (Sunday)")

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
    schedule_type = str(getattr(report, "schedule_type", "") or MONTHLY).lower()
    schedule_day = int(report.schedule_day or 1)
    schedule_hour = max(0, min(int(report.schedule_hour or 0), 23))
    if schedule_type == WEEKLY:
        schedule_day = max(1, min(schedule_day, 7))
        days_until_schedule = (schedule_day - 1 - now.weekday()) % 7
        candidate = (now + timedelta(days=days_until_schedule)).replace(
            hour=schedule_hour,
            minute=0,
            second=0,
            microsecond=0,
        )
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate

    schedule_day = max(1, min(schedule_day, 28))
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

    Return one full reporting period ending at run_at.

    Report content is determined by schedule type, never by last_run_at:
    monthly reports cover the preceding calendar month; weekly reports cover
    the preceding seven days. This keeps Preview, manual runs and scheduled
    runs comparable even when a report is run more than once.
    """
    run_at = ensure_utc_naive(run_at) or utcnow_naive()
    schedule_type = str(getattr(report, "schedule_type", "") or MONTHLY).lower()
    if schedule_type == WEEKLY:
        return run_at - timedelta(days=7), run_at
    return _subtract_one_month(run_at), run_at


def compute_previous_report_interval(report, from_dt, to_dt):
    """
    Return the previous comparable report interval.
    """
    from_dt = ensure_utc_naive(from_dt)
    to_dt = ensure_utc_naive(to_dt)
    if from_dt is None or to_dt is None:
        return None, None
    schedule_type = str(getattr(report, "schedule_type", "") or MONTHLY).lower()
    if schedule_type == WEEKLY:
        return from_dt - timedelta(days=7), from_dt
    if schedule_type != MONTHLY:
        return None, None
    return _subtract_one_month(from_dt), from_dt


def compute_report_ptr_cutoff(reference_dt, months=6):
    """
    Return the minimum last_seen datetime accepted for report PTR hostnames.
    """
    reference_dt = ensure_utc_naive(reference_dt)
    if reference_dt is None:
        return None
    return _add_months(reference_dt, -int(months or 6))


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


def collect_report_requested_fqdns(indexer, results):
    """
    Collect per-IP user-requested FQDNs from Kvrocks fqdn_requested indexes.
    """
    per_ip_fqdns = {}
    for ip, uids in (results or {}).items():
        ip_fqdns = set()
        pipe = indexer.r.pipeline(transaction=False)
        for uid in uids:
            pipe.smembers(f"fqdn_requesteds:{uid}")
        for fqdns in pipe.execute():
            for fqdn in fqdns or []:
                fqdn_value = str(fqdn).strip().lower().rstrip(".")
                if fqdn_value:
                    ip_fqdns.add(fqdn_value)
        per_ip_fqdns[ip] = sorted(ip_fqdns, key=str.lower)
    return per_ip_fqdns


def _normalize_report_fqdn(value):
    """
    Normalize a report hostname candidate and reject IP literals.
    """
    normalized = str(value or "").strip().lower().rstrip(".")
    if not normalized or "." not in normalized:
        return ""
    try:
        ipaddress.ip_address(normalized)
        return ""
    except ValueError:
        return normalized


def collect_report_ptr_fqdns(
    document_loader,
    results,
    timestamps=None,
    min_last_seen_ts=None,
):
    """
    Collect recent PTR hostnames found in the report interval documents.
    """
    per_ip_ptrs = {}
    for ip, uids in (results or {}).items():
        ip_ptrs = []
        seen = set()
        for uid in uids or []:
            if min_last_seen_ts is not None:
                uid_timestamps = (timestamps or {}).get(ip, {}).get(uid, {})
                last_seen_ts = uid_timestamps.get("last_seen")
                if last_seen_ts is None or int(last_seen_ts) < int(min_last_seen_ts):
                    continue

            document = document_loader(uid)
            if not document:
                continue
            body = document.get("body") or {}
            for entry in body.get("hostnames") or []:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("type") or "").upper() != "PTR":
                    continue
                fqdn = _normalize_report_fqdn(
                    entry.get("name") or entry.get("hostname")
                )
                if not fqdn or fqdn in seen:
                    continue
                seen.add(fqdn)
                ip_ptrs.append(fqdn)
        per_ip_ptrs[ip] = sorted(ip_ptrs, key=str.lower)
    return per_ip_ptrs


def _parse_pdns_ndjson(payload):
    """
    Parse CIRCL Passive DNS NDJSON payload into dictionaries.
    """
    records = []
    for line in (payload or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _extract_pdns_fqdn(record):
    """
    Extract a hostname from one CIRCL Passive DNS A record.
    """
    record_type = str((record or {}).get("rrtype") or (record or {}).get("type") or "")
    if record_type and record_type.upper() != "A":
        return ""

    for key in ("rdata", "rrdata", "rrname", "name", "hostname", "fqdn"):
        value = (record or {}).get(key)
        values = value if isinstance(value, list) else [value]
        for candidate in values:
            fqdn = _normalize_report_fqdn(candidate)
            if fqdn:
                return fqdn
    return ""


def _extract_pdns_last_seen(record):
    """Return a validated CIRCL Passive DNS ``time_last`` epoch timestamp."""
    value = (record or {}).get("time_last")
    if isinstance(value, bool):
        return None
    try:
        timestamp = int(value)
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return timestamp if timestamp > 0 else None


def _format_pdns_last_seen(timestamp):
    """Format a validated Passive DNS timestamp or return the fallback label."""
    if timestamp is None:
        return "N/A"
    try:
        return _format_datetime(datetime.fromtimestamp(timestamp, tz=timezone.utc))
    except (OverflowError, OSError, TypeError, ValueError):
        return "N/A"


def collect_report_passive_dns_fqdns(
    app_config,
    ips,
    per_ip_requested_fqdns,
    progress_callback=None,
):
    """
    Collect Passive DNS hostnames to fill each IP's associated FQDN list.
    """
    ips = list(ips or [])

    def update_progress(done):
        if progress_callback:
            progress_callback(done, len(ips))

    update_progress(0)
    passive_user = str(app_config.get("PASSIVE_USER", "") or "").strip()
    passive_pwd = str(app_config.get("PASSIVE_PWD", "") or "")
    if not passive_user or not passive_pwd:
        update_progress(len(ips))
        return {}

    per_ip_pdns = {}
    for done, ip in enumerate(ips, start=1):
        requested_fqdns = (
            per_ip_requested_fqdns.get(ip, []) if per_ip_requested_fqdns else []
        )
        remaining = REPORT_FQDN_LIMIT - len(requested_fqdns)
        if remaining <= 0:
            update_progress(done)
            continue

        seen = {str(fqdn).lower() for fqdn in requested_fqdns}
        pdns_fqdns = []
        try:
            response = requests.get(
                f"https://www.circl.lu/pdns/query/{ip}",
                auth=(passive_user, passive_pwd),
                headers={"dribble-disable-active-query": "1"},
                timeout=15,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            logger.warning("Report passive DNS failed for %s: %s", ip, error)
            update_progress(done)
            continue

        for record in _parse_pdns_ndjson(response.text):
            fqdn = _extract_pdns_fqdn(record)
            if not fqdn or fqdn in seen:
                continue
            seen.add(fqdn)
            pdns_fqdns.append(
                {
                    "fqdn": fqdn,
                    "last_seen": _extract_pdns_last_seen(record),
                }
            )
            if len(pdns_fqdns) >= remaining:
                break

        if pdns_fqdns:
            per_ip_pdns[ip] = pdns_fqdns
        update_progress(done)
    return per_ip_pdns


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


def _normalize_report_pdns_entry(entry):
    """Normalize current and legacy Passive DNS report entry shapes."""
    if isinstance(entry, dict):
        fqdn = _normalize_report_fqdn(entry.get("fqdn"))
        last_seen = entry.get("last_seen")
    else:
        fqdn = _normalize_report_fqdn(entry)
        last_seen = None
    return fqdn, last_seen


def _report_associated_fqdns(ptr_fqdns, requested_fqdns, pdns_fqdns):
    """Return deduplicated report FQDNs in their established source order."""
    seen_associated = set()
    associated_entries = []
    for fqdn in ptr_fqdns:
        fqdn_key = str(fqdn).lower()
        if fqdn_key in seen_associated:
            continue
        seen_associated.add(fqdn_key)
        associated_entries.append((fqdn, "ptr", None))
    for fqdn in requested_fqdns:
        fqdn_key = str(fqdn).lower()
        if fqdn_key in seen_associated:
            continue
        seen_associated.add(fqdn_key)
        associated_entries.append((fqdn, "", None))
    for entry in pdns_fqdns:
        fqdn, last_seen = _normalize_report_pdns_entry(entry)
        fqdn_key = fqdn.lower()
        if not fqdn or fqdn_key in seen_associated:
            continue
        seen_associated.add(fqdn_key)
        associated_entries.append((fqdn, "pdns", last_seen))
    return associated_entries


def _report_host_lines(ip, _uids, report_data):  # pylint: disable=too-many-locals
    """Render one host and its associated FQDNs as Markdown list lines."""
    per_ip_ports = report_data["ports"]
    per_ip_tags = report_data["tags"]
    per_ip_requested_fqdns = report_data["requested_fqdns"]
    per_ip_ptr_fqdns = report_data["ptr_fqdns"]
    per_ip_pdns_fqdns = report_data["pdns_fqdns"]
    tags = per_ip_tags.get(ip, []) if per_ip_tags else []
    requested_fqdns = (
        per_ip_requested_fqdns.get(ip, []) if per_ip_requested_fqdns else []
    )
    ptr_fqdns = per_ip_ptr_fqdns.get(ip, []) if per_ip_ptr_fqdns else []
    pdns_fqdns = per_ip_pdns_fqdns.get(ip, []) if per_ip_pdns_fqdns else []
    ports = per_ip_ports.get(ip) or []
    ports_text = ", ".join(ports) if ports else "none"
    lines = [f"- {ip}"]
    if tags:
        lines.append(f"  - Tag: {', '.join(tags)}")
    lines.extend(
        [
            f"  - Open ports: {ports_text}",
        ]
    )
    associated_entries = _report_associated_fqdns(
        ptr_fqdns,
        requested_fqdns,
        pdns_fqdns,
    )
    associated_count = len(associated_entries)
    if associated_count:
        lines.append(f"  - Associated FQDNs ({associated_count})")
        for fqdn, source, last_seen in associated_entries[:REPORT_FQDN_LIMIT]:
            if source == "pdns":
                lines.append(
                    f"    - {fqdn} (pdns) — last seen: "
                    f"{_format_pdns_last_seen(last_seen)}"
                )
            else:
                suffix = f" ({source})" if source else ""
                lines.append(f"    - {fqdn}{suffix}")
        if associated_count > REPORT_FQDN_LIMIT:
            remaining_count = associated_count - REPORT_FQDN_LIMIT
            lines.append(f"    - {remaining_count} additional fqdn not listed here")
    return lines


def _report_protocol_groups(results, per_ip_tags):
    """Split report IPs into web, mail, and unclassified protocol views."""
    groups = {"Web hosts": [], "Mail related": [], "Other": []}
    for ip in sorted(results, key=_ip_sort_key):
        tags = set(per_ip_tags.get(ip, []) if per_ip_tags else [])
        is_web = bool(tags & REPORT_WEB_PROTOCOL_TAGS)
        is_mail = bool(tags & REPORT_MAIL_PROTOCOL_TAGS)
        if is_web:
            groups["Web hosts"].append(ip)
        if is_mail:
            groups["Mail related"].append(ip)
        if not is_web and not is_mail:
            groups["Other"].append(ip)
    return groups


def _fqdn_domain_sort_key(fqdn):
    """Sort FQDNs by their domain labels before their hostname labels."""
    return tuple(reversed(str(fqdn).rstrip(".").lower().split(".")))


def _report_detected_fqdns(per_ip_ptr_fqdns, per_ip_requested_fqdns):
    """Return unique non-Passive-DNS FQDNs, sorted by domain."""
    detected = {}
    for per_ip_fqdns in (per_ip_ptr_fqdns or {}, per_ip_requested_fqdns or {}):
        for fqdns in per_ip_fqdns.values():
            for fqdn in fqdns:
                normalized = str(fqdn).strip()
                if normalized:
                    detected.setdefault(normalized.lower(), normalized)
    return sorted(detected.values(), key=_fqdn_domain_sort_key)


def _report_passive_dns_fqdns(per_ip_pdns_fqdns):
    """Return unique Passive DNS FQDNs and their most recent observation."""
    detected = {}
    for entries in (per_ip_pdns_fqdns or {}).values():
        for entry in entries:
            fqdn, last_seen = _normalize_report_pdns_entry(entry)
            if not fqdn:
                continue
            key = fqdn.lower()
            previous = detected.get(key)
            if previous is None or (last_seen or 0) > (previous[1] or 0):
                detected[key] = (fqdn, last_seen)
    return sorted(detected.values(), key=lambda entry: _fqdn_domain_sort_key(entry[0]))


def build_report_markdown(
    report,
    search_results,
    per_ip_ports,
    port_counter,
    from_dt,
    to_dt,
    per_ip_tags=None,
    per_ip_requested_fqdns=None,
    per_ip_ptr_fqdns=None,
    per_ip_pdns_fqdns=None,
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

    if str(getattr(report, "schedule_type", "") or "").lower() in REPORT_SCHEDULE_TYPES:
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

    report_data = {
        "ports": per_ip_ports,
        "tags": per_ip_tags,
        "requested_fqdns": per_ip_requested_fqdns,
        "ptr_fqdns": per_ip_ptr_fqdns,
        "pdns_fqdns": per_ip_pdns_fqdns,
    }
    detected_fqdns = _report_detected_fqdns(per_ip_ptr_fqdns, per_ip_requested_fqdns)
    if detected_fqdns:
        lines.extend(["", "## FQDN detected", ""])
        lines.extend(f"- {fqdn}" for fqdn in detected_fqdns)

    passive_dns_fqdns = _report_passive_dns_fqdns(per_ip_pdns_fqdns)
    if passive_dns_fqdns:
        lines.extend(["", "## Passive DNS FQDN detected", ""])
        lines.extend(
            f"- {fqdn} — last seen: {_format_pdns_last_seen(last_seen)}"
            for fqdn, last_seen in passive_dns_fqdns
        )

    for section, ips in _report_protocol_groups(results, per_ip_tags).items():
        if not ips:
            continue
        lines.extend(["", f"## {section}", ""])
        for ip in ips:
            lines.extend(_report_host_lines(ip, results[ip], report_data))

    lines.extend(["", "## Hosts", ""])
    if not results:
        lines.append("No matching hosts.")
    else:
        for ip in sorted(results, key=_ip_sort_key):
            lines.extend(_report_host_lines(ip, results[ip], report_data))

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
