"""
Helpers for scheduled Markdown reports.
"""

# pylint: disable=too-many-lines

import calendar
from io import BytesIO
from html import escape
import ipaddress
import json
import logging
import re
import smtplib
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import requests
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from .timeutils import ensure_utc_naive, utcnow_naive

logger = logging.getLogger("flask_appbuilder")
EMAIL_SPLIT_RE = re.compile(r"[\n,;]+")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MONTHLY = "monthly"
WEEKLY = "weekly"
REPORT_SCHEDULE_TYPES = frozenset((MONTHLY, WEEKLY))
REPORT_FQDN_LIMIT = 25
REPORT_PDNS_ACTIVE_DAYS = 90
REPORT_WEB_PROTOCOL_TAGS = frozenset(("proto:http", "proto:https"))
REPORT_MAIL_PROTOCOL_TAGS = frozenset(("proto:smtp", "proto:imap", "proto:pop3"))
REPORT_REMOTE_ACCESS_TAGS = frozenset(
    ("type:vpn", "proto:ssh", "proto:telnet", "proto:rdp")
)
REPORT_HIDDEN_TAGS = frozenset(("domain:circl.lu",))
REPORT_WEBSERVICES_SECTION = "Webservices related host"
REPORT_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
REPORT_LIST_RE = re.compile(r"^(\s*)-\s+(.+?)\s*$")
REPORT_INLINE_CODE_RE = re.compile(r"(`[^`]*`)")
REPORT_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
REPORT_IP_LITERAL_RE = re.compile(r"(?<![0-9a-f:.])([0-9a-f:.]+)(?![0-9a-f:.])", re.I)
REPORT_PDF_LIST_RE = re.compile(r"^(\s*)-\s+(.+?)\s*$")


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


def group_new_open_ports_by_port(new_open_ports):
    """Group newly opened ports by port, with numerically sorted IPs."""
    per_port_ips = {}
    for ip, ports in (new_open_ports or {}).items():
        for port in ports:
            per_port_ips.setdefault(port, []).append(ip)
    return {
        port: sorted(ips, key=_ip_sort_key)
        for port, ips in sorted(
            per_port_ips.items(), key=lambda item: _port_sort_key(item[0])
        )
    }


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


def _report_display_tags(tags):
    """Hide redundant vendor tags when an equivalent product tag exists."""
    product_values = set()
    for tag in tags:
        namespace, separator, value = str(tag).partition(":")
        if separator and namespace.lower() == "product":
            product_values.add(value.lower())

    displayed = []
    for tag in tags:
        namespace, separator, value = str(tag).partition(":")
        if str(tag).lower() in REPORT_HIDDEN_TAGS:
            continue
        if (
            separator
            and namespace.lower() == "vendor"
            and value.lower() in product_values
        ):
            continue
        displayed.append(tag)
    return displayed


def _report_host_lines(ip, _uids, report_data):  # pylint: disable=too-many-locals
    """Render one host and its associated FQDNs as Markdown list lines."""
    per_ip_ports = report_data["ports"]
    per_ip_tags = report_data["tags"]
    per_ip_requested_fqdns = report_data["requested_fqdns"]
    per_ip_ptr_fqdns = report_data["ptr_fqdns"]
    per_ip_pdns_fqdns = report_data["pdns_fqdns"]
    tags = _report_display_tags(per_ip_tags.get(ip, []) if per_ip_tags else [])
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
    """Split report IPs into web, mail, remote-access, and other views."""
    groups = {
        REPORT_WEBSERVICES_SECTION: [],
        "Mail related": [],
        "Remote access": [],
        "Other": [],
    }
    for ip in sorted(results, key=_ip_sort_key):
        tags = set(per_ip_tags.get(ip, []) if per_ip_tags else [])
        is_web = bool(tags & REPORT_WEB_PROTOCOL_TAGS)
        is_mail = bool(tags & REPORT_MAIL_PROTOCOL_TAGS)
        is_remote_access = bool(tags & REPORT_REMOTE_ACCESS_TAGS)
        if is_web:
            groups[REPORT_WEBSERVICES_SECTION].append(ip)
        if is_mail:
            groups["Mail related"].append(ip)
        if is_remote_access:
            groups["Remote access"].append(ip)
        if not is_web and not is_mail and not is_remote_access:
            groups["Other"].append(ip)
    return groups


def _fqdn_domain_sort_key(fqdn):
    """Sort FQDNs by their domain labels before their hostname labels."""
    return tuple(reversed(str(fqdn).rstrip(".").lower().split(".")))


def _report_detected_fqdns(per_ip_ptr_fqdns, per_ip_requested_fqdns):
    """Return non-Passive-DNS FQDNs with their affected IPs, sorted by domain."""
    detected = {}
    for per_ip_fqdns in (per_ip_ptr_fqdns or {}, per_ip_requested_fqdns or {}):
        for ip, fqdns in per_ip_fqdns.items():
            for fqdn in fqdns:
                normalized = str(fqdn).strip()
                if normalized:
                    entry = detected.setdefault(normalized.lower(), [normalized, set()])
                    entry[1].add(ip)
    return [
        (fqdn, sorted(ips, key=_ip_sort_key))
        for fqdn, ips in sorted(
            detected.values(), key=lambda entry: _fqdn_domain_sort_key(entry[0])
        )
    ]


def _report_passive_dns_fqdns(per_ip_pdns_fqdns, active_since):
    """Return active Passive DNS FQDNs with affected IPs and latest observation."""
    detected = {}
    for ip, entries in (per_ip_pdns_fqdns or {}).items():
        for entry in entries:
            fqdn, last_seen = _normalize_report_pdns_entry(entry)
            if not fqdn or last_seen is None or last_seen < active_since:
                continue
            key = fqdn.lower()
            previous = detected.get(key)
            if previous is None:
                detected[key] = [fqdn, {ip}, last_seen]
                continue
            previous[1].add(ip)
            if last_seen > previous[2]:
                previous[0] = fqdn
                previous[2] = last_seen
    return [
        (fqdn, sorted(ips, key=_ip_sort_key), last_seen)
        for fqdn, ips, last_seen in sorted(
            detected.values(), key=lambda entry: _fqdn_domain_sort_key(entry[0])
        )
    ]


def _report_host_anchor_id(ip):
    """Return the stable Full report dump anchor for one IP."""
    try:
        normalized_ip = ipaddress.ip_address(str(ip)).compressed
        return f"host-{normalized_ip.replace('.', '-').replace(':', '-')}"
    except ValueError:
        return ""


def _render_report_text(text, link_ips=False):
    """Escape text, optionally linking IP literals to their host dump anchors."""
    if not link_ips:
        return escape(text)

    rendered = []
    position = 0
    for match in REPORT_IP_LITERAL_RE.finditer(text):
        ip = match.group(1)
        anchor_id = _report_host_anchor_id(ip)
        if not anchor_id:
            continue
        rendered.append(escape(text[position : match.start()]))
        rendered.append(f'<a href="#{anchor_id}">{escape(ip)}</a>')
        position = match.end()
    rendered.append(escape(text[position:]))
    return "".join(rendered)


def _render_report_inline(text, link_ips=False):
    """Escape report text while retaining inline-code presentation."""
    rendered = []
    for part in REPORT_INLINE_CODE_RE.split(str(text)):
        if part.startswith("`") and part.endswith("`"):
            rendered.append(f"<code>{escape(part[1:-1])}</code>")
        else:
            escaped_parts = REPORT_BOLD_RE.split(part)
            rendered.extend(
                (
                    f"<strong>{_render_report_text(value, link_ips)}</strong>"
                    if index % 2
                    else _render_report_text(value, link_ips)
                )
                for index, value in enumerate(escaped_parts)
            )
    return "".join(rendered)


def _render_report_list_item(text, link_ips=False):
    """Render a report list item, exposing host tags as simple HTML code tags."""
    label, separator, tag_values = str(text).partition(": ")
    if label != "Tag" or not separator:
        return _render_report_inline(text, link_ips)
    tags = [tag.strip() for tag in tag_values.split(",") if tag.strip()]
    return "Tag: " + " ".join(f"<code>{escape(tag)}</code>" for tag in tags)


def _report_heading_id(text, heading_ids):
    """Create a predictable unique fragment identifier for a heading."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "section"
    heading_ids[slug] = heading_ids.get(slug, 0) + 1
    return slug if heading_ids[slug] == 1 else f"{slug}-{heading_ids[slug]}"


def render_report_markdown_html(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    markdown_body,
):
    """Render Plum report Markdown subset as escaped HTML with a heading index."""
    lines = []
    headings = []
    paragraphs = []
    list_depth = 0
    list_item_open = []
    heading_ids = {}
    toc_insert_at = None
    current_section = ""

    def close_paragraph():
        if paragraphs:
            lines.append(f"<p>{_render_report_inline(' '.join(paragraphs))}</p>")
            paragraphs.clear()

    def close_lists():
        nonlocal list_depth
        while list_depth:
            if list_item_open[-1]:
                lines.append("</li>")
            lines.append("</ul>")
            list_item_open.pop()
            list_depth -= 1

    for source_line in str(markdown_body or "").splitlines():
        heading_match = REPORT_HEADING_RE.match(source_line)
        list_match = REPORT_LIST_RE.match(source_line)
        if heading_match:
            close_paragraph()
            close_lists()
            level = len(heading_match.group(1))
            title = heading_match.group(2)
            if level == 2:
                current_section = title
            if level > 1 and toc_insert_at is None:
                toc_insert_at = len(lines)
            heading_id = _report_heading_id(title, heading_ids)
            lines.append(
                f'<h{level} id="{heading_id}">{_render_report_inline(title)}</h{level}>'
            )
            if level > 1:
                headings.append((level, title, heading_id))
            continue
        if list_match:
            close_paragraph()
            target_depth = len(list_match.group(1).expandtabs(2)) // 2 + 1
            while list_depth > target_depth:
                if list_item_open[-1]:
                    lines.append("</li>")
                lines.append("</ul>")
                list_item_open.pop()
                list_depth -= 1
            while list_depth < target_depth:
                lines.append("<ul>")
                list_item_open.append(False)
                list_depth += 1
            if list_item_open[-1]:
                lines.append("</li>")
            item = list_match.group(2)
            anchor_id = ""
            if current_section == "Full report dump" and target_depth == 1:
                anchor_id = _report_host_anchor_id(item)
            link_ips = current_section in {
                "New opened port",
                "FQDN detected",
                "FQDN discovered in Passive DNS",
            }
            anchor_attribute = f' id="{anchor_id}"' if anchor_id else ""
            lines.append(
                f"<li{anchor_attribute}>{_render_report_list_item(item, link_ips)}"
            )
            list_item_open[-1] = True
            continue
        if not source_line.strip():
            close_paragraph()
            close_lists()
            continue
        close_lists()
        paragraphs.append(source_line.strip())

    close_paragraph()
    close_lists()
    toc = ""
    if headings:
        toc_items = "".join(
            f'<li class="report-toc-level-{level}"><a href="#{heading_id}">'
            f"{_render_report_inline(title)}</a></li>"
            for level, title, heading_id in headings
        )
        toc = f'<nav class="report-toc" aria-label="Report index"><h2>Index</h2><ul>{toc_items}</ul></nav>'
    if toc and toc_insert_at is not None:
        lines.insert(toc_insert_at, toc)
    else:
        lines.insert(0, toc)
    return f'<article class="report-html">{"".join(lines)}</article>'


def _render_report_pdf_text(text, link_ips=False):
    """Escape PDF text, optionally linking IP literals to host destinations."""
    if not link_ips:
        return escape(text)

    rendered = []
    position = 0
    for match in REPORT_IP_LITERAL_RE.finditer(text):
        ip = match.group(1)
        anchor_id = _report_host_anchor_id(ip)
        if not anchor_id:
            continue
        rendered.append(escape(text[position : match.start()]))
        rendered.append(f'<a href="#{anchor_id}">{escape(ip)}</a>')
        position = match.end()
    rendered.append(escape(text[position:]))
    return "".join(rendered)


def _render_report_pdf_inline(text, link_ips=False):
    """Escape report text for ReportLab's small Paragraph markup subset."""
    rendered = []
    for part in REPORT_INLINE_CODE_RE.split(str(text)):
        if part.startswith("`") and part.endswith("`"):
            rendered.append(f'<font name="Courier">{escape(part[1:-1])}</font>')
            continue
        bold_parts = REPORT_BOLD_RE.split(part)
        rendered.extend(
            (
                f"<b>{_render_report_pdf_text(value, link_ips)}</b>"
                if index % 2
                else _render_report_pdf_text(value, link_ips)
            )
            for index, value in enumerate(bold_parts)
        )
    return "".join(rendered)


def generate_report_pdf(report_name, markdown_body):  # pylint: disable=too-many-locals
    """Generate a PDF with cover, linked index, and one page per H2 section."""
    cover_title = str(report_name or "Report")
    cover_title = cover_title[:1].upper() + cover_title[1:]
    markdown_lines = str(markdown_body or "").splitlines()
    heading_ids = {}
    sections = []
    for source_line in markdown_lines:
        heading_match = REPORT_HEADING_RE.match(source_line)
        if heading_match and len(heading_match.group(1)) == 2:
            section_title = heading_match.group(2)
            sections.append(
                (section_title, _report_heading_id(section_title, heading_ids))
            )
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=cover_title,
        author="P.L.U.M.",
    )
    styles = getSampleStyleSheet()
    cover_style = ParagraphStyle(
        "ReportCover",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=30,
        leading=36,
    )
    section_style = ParagraphStyle(
        "ReportSection",
        parent=styles["Heading1"],
        spaceAfter=0.35 * cm,
    )
    subsection_style = ParagraphStyle(
        "ReportSubsection",
        parent=styles["Heading2"],
        spaceBefore=0.2 * cm,
        spaceAfter=0.2 * cm,
    )
    paragraph_style = ParagraphStyle(
        "ReportParagraph",
        parent=styles["BodyText"],
        leading=14,
        spaceAfter=0.18 * cm,
    )

    story = [
        Spacer(1, 11 * cm),
        Paragraph(_render_report_pdf_inline(cover_title), cover_style),
        PageBreak(),
        Paragraph("Index", section_style),
    ]
    for title, section_id in sections:
        story.append(
            Paragraph(
                f'• <a href="#{section_id}">{_render_report_pdf_inline(title)}</a>',
                paragraph_style,
            )
        )
    story.append(PageBreak())

    current_section = ""
    section_index = 0
    for source_line in markdown_lines:
        heading_match = REPORT_HEADING_RE.match(source_line)
        list_match = REPORT_PDF_LIST_RE.match(source_line)
        if heading_match:
            level = len(heading_match.group(1))
            title = heading_match.group(2)
            if level == 1:
                continue
            if level == 2:
                current_section = title
                section_id = sections[section_index][1]
                section_index += 1
                story.extend(
                    [
                        PageBreak(),
                        Paragraph(
                            f'<a name="{section_id}"/>'
                            f"{_render_report_pdf_inline(title)}",
                            section_style,
                        ),
                    ]
                )
            else:
                story.append(
                    Paragraph(_render_report_pdf_inline(title), subsection_style)
                )
            continue
        if not source_line.strip():
            story.append(Spacer(1, 0.12 * cm))
            continue
        if list_match:
            depth = len(list_match.group(1).expandtabs(2)) // 2
            item = list_match.group(2)
            anchor_id = ""
            if current_section == "Full report dump" and depth == 0:
                anchor_id = _report_host_anchor_id(item)
            link_ips = current_section in {
                "New opened port",
                "FQDN detected",
                "FQDN discovered in Passive DNS",
            }
            anchor_markup = f'<a name="{anchor_id}"/>' if anchor_id else ""
            list_style = ParagraphStyle(
                f"ReportList{depth}",
                parent=paragraph_style,
                leftIndent=(depth + 1) * 0.45 * cm,
                firstLineIndent=-0.3 * cm,
            )
            story.append(
                Paragraph(
                    f"{anchor_markup}• {_render_report_pdf_inline(item, link_ips)}",
                    list_style,
                )
            )
            continue
        story.append(
            Paragraph(_render_report_pdf_inline(source_line.strip()), paragraph_style)
        )

    document.build(story)
    return buffer.getvalue()


def build_report_markdown(  # pylint: disable=too-many-statements
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
    report_name = str(report.name or "")
    report_title = report_name[:1].upper() + report_name[1:]

    lines = [
        f"# Report for {report_title}.",
        "",
        f"- Query: `{report.query}`",
        f"- Period: {_format_datetime(from_dt)} to {_format_datetime(to_dt)}",
        f"- Matching IPs: {total_ips}",
        f"- Matching scans: {total_scans}",
        "",
        "## Open ports",
        "",
        "This section summarizes the total number of hosts exposing each open "
        "port during the report period.",
        "",
    ]

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
        lines.extend(
            [
                "Ports newly observed as open during this report period, compared "
                "with the preceding equivalent period.",
                "",
            ]
        )
        if new_open_ports:
            for port, ips in group_new_open_ports_by_port(new_open_ports).items():
                lines.append(f"- **{port}**")
                lines.extend(f"  - {ip}" for ip in ips)
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
        lines.extend(
            [
                "FQDNs (Fully Qualified domain names) detected from scanned hosts. "
                "These hostnames can be collected from any scan result fields, "
                "including records within certificates.",
                "",
            ]
        )
        lines.extend(f"- {fqdn} ({', '.join(ips)})" for fqdn, ips in detected_fqdns)

    report_end = ensure_utc_naive(to_dt or utcnow_naive())
    active_since = int(
        (report_end - timedelta(days=REPORT_PDNS_ACTIVE_DAYS))
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )
    passive_dns_fqdns = _report_passive_dns_fqdns(per_ip_pdns_fqdns, active_since)
    if passive_dns_fqdns:
        lines.extend(["", "## FQDN discovered in Passive DNS", ""])
        lines.append(
            "Additional Passive DNS records not detected, observed within the last 90 days."
        )
        lines.append("")
        lines.extend(
            f"- {fqdn} ({', '.join(ips)}) — last seen: "
            f"{_format_pdns_last_seen(last_seen)}"
            for fqdn, ips, last_seen in passive_dns_fqdns
        )

    for section, ips in _report_protocol_groups(results, per_ip_tags).items():
        if not ips:
            continue
        lines.extend(["", f"## {section}", ""])
        if section == REPORT_WEBSERVICES_SECTION:
            lines.extend(["Hosts with at least one exposed web service.", ""])
        elif section == "Mail related":
            lines.extend(["Hosts with at least one exposed mail service.", ""])
        elif section == "Remote access":
            lines.extend(
                [
                    "Hosts with at least one exposed VPN, SSH, Telnet, or RDP service.",
                    "",
                ]
            )
        for ip in ips:
            lines.extend(_report_host_lines(ip, results[ip], report_data))

    lines.extend(["", "## Full report dump", ""])
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
    message.add_alternative(render_report_markdown_html(markdown_body), subtype="html")

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with smtp_class(smtp_host, smtp_port, timeout=30) as smtp:
        if use_tls and not use_ssl:
            smtp.starttls()
        if smtp_user:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)
