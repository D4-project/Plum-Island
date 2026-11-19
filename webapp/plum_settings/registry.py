"""Explicit, typed inventory of Plum's operational configuration."""

from dataclasses import dataclass
import ipaddress
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

from email_validator import EmailNotValidError, validate_email


class SettingsError(ValueError):
    """A safe, user-facing error that never includes submitted values."""


@dataclass(frozen=True)
class Setting:  # pylint: disable=too-many-instance-attributes
    """One supported field, including its default and application contract."""

    key: str
    label: str
    default: object
    help: str
    unit: str = ""
    kind: str = ""
    minimum: float | None = None
    secret: bool = False
    optional: bool = False
    inactive: bool = False

    @property
    def value_type(self):
        """Infer scalar controls from the documented default."""
        return self.kind or type(self.default).__name__


@dataclass(frozen=True)
class Section:
    """An explanatory card and the processes that consume its values."""

    title: str
    help: str
    restart: str
    fields: tuple


SECTIONS = (
    Section(
        "Connectivity to Meilisearch",
        "Connect Plum to the document search engine used for token search and background indexing.",
        "Web application, scheduler and indexing worker",
        (
            Setting(
                "MEILI_DATABASE_URI",
                "Server URL",
                "http://localhost:7700",
                "Base HTTP or HTTPS URL of your Meilisearch server.",
                kind="url",
            ),
            Setting(
                "MEILI_KEY",
                "API key",
                "",
                "Key used by Plum to read and write search documents. Replace the installation example key "
                "before production use.",
                secret=True,
            ),
            Setting(
                "MEILI_HTTP_TIMEOUT_SECONDS",
                "Request timeout",
                10,
                "Maximum duration of a Meilisearch HTTP request; this is not a document indexing task timeout.",
                "seconds",
                minimum=1,
            ),
        ),
    ),
    Section(
        "Connectivity to Kvrocks",
        "Connect Plum to the structured search index and indexing coordination state.",
        "Web application, scheduler and indexing worker",
        (
            Setting(
                "KVROCKS_HOST",
                "Server host",
                "localhost",
                "Hostname or IP address of the Kvrocks server; do not include a URL scheme.",
                kind="host",
            ),
            Setting(
                "KVROCKS_PORT",
                "Server port",
                6666,
                "TCP port used for Kvrocks commands.",
                kind="port",
            ),
            Setting(
                "KVROCKS_SOCKET_TIMEOUT_SECONDS",
                "Socket timeout",
                10,
                "Maximum wait for a Kvrocks socket operation.",
                "seconds",
                minimum=1,
            ),
        ),
    ),
    Section(
        "Connectivity to CIRCL services",
        "Configure passive DNS credentials and background network enrichment.",
        "Web application and scheduler",
        (
            Setting(
                "PASSIVE_USER",
                "Passive DNS username",
                "",
                "Account used for passive DNS lookups in IP details, reports and exports.",
                optional=True,
            ),
            Setting(
                "PASSIVE_PWD",
                "Passive DNS password",
                "",
                "Password for the passive DNS account. Leave unset when this service is not used.",
                secret=True,
                optional=True,
            ),
            Setting(
                "NETWORK_LOOKUP_TIMEOUT_SECONDS",
                "Network lookup timeout",
                10,
                "Maximum duration of one network enrichment request.",
                "seconds",
                minimum=1,
            ),
            Setting(
                "NETWORK_REFRESH_BATCH_SIZE",
                "Refresh batch size",
                32,
                "Maximum pending target network refreshes handled per scheduler pass.",
                "targets",
                minimum=1,
            ),
        ),
    ),
    Section(
        "Connectivity to the mail server",
        "Deliver scheduled report summaries and PDF attachments through SMTP.",
        "Web application and scheduler",
        (
            Setting(
                "REPORT_SMTP_HOST",
                "SMTP host",
                "",
                "Leave unset to disable report email delivery.",
                kind="host",
                optional=True,
            ),
            Setting(
                "REPORT_SMTP_PORT",
                "SMTP port",
                25,
                "Port exposed by your SMTP server; select the matching TLS mode below.",
                kind="port",
            ),
            Setting(
                "REPORT_SMTP_USER",
                "SMTP username",
                "",
                "Leave unset for a server that accepts mail without authentication.",
                optional=True,
            ),
            Setting(
                "REPORT_SMTP_PASSWORD",
                "SMTP password",
                "",
                "Password used for SMTP authentication.",
                secret=True,
                optional=True,
            ),
            Setting(
                "REPORT_SMTP_FROM",
                "Sender address",
                "",
                "Leave unset to use the SMTP username, then plum-reports@localhost as the fallback.",
                kind="email",
                optional=True,
            ),
            Setting(
                "REPORT_SMTP_USE_TLS",
                "Use STARTTLS",
                False,
                "Upgrade the SMTP connection to TLS. Cannot be combined with implicit TLS.",
            ),
            Setting(
                "REPORT_SMTP_USE_SSL",
                "Use implicit TLS",
                False,
                "Start the SMTP connection inside TLS. Cannot be combined with STARTTLS.",
            ),
        ),
    ),
    Section(
        "Scanning and scheduling",
        "Control scheduler cadence, queue filling and bounded maintenance work.",
        "Web application and scheduler",
        (
            Setting(
                "SCAN_DELAY",
                "Legacy scan delay",
                12,
                "Inactive: scan frequency is configured per scan profile; this legacy value has no current "
                "runtime consumer.",
                "hours",
                inactive=True,
            ),
            Setting(
                "SCHEDULER_DELAY",
                "Scheduler interval",
                10,
                "Interval between scan orchestration, maintenance and network enrichment passes.",
                "minutes",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_QUEUE_TARGET_JOBS_PER_PROFILE",
                "Waiting queue target",
                256,
                "Desired waiting jobs for each scan profile.",
                "jobs",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_QUEUE_STATE_BATCH_SIZE",
                "Queue transaction size",
                256,
                "Target/profile states staged in one transaction; the scheduler caps this at 256.",
                "states",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_STATE_SYNC_BATCH_SIZE",
                "State seeding batch",
                2048,
                "Maximum missing target/profile runtime rows created per scheduler pass.",
                "rows",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_QUEUE_MAX_NEW_JOBS_PER_TICK",
                "New jobs per pass",
                1024,
                "Maximum new queued jobs created during one scheduler pass.",
                "jobs",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_QUEUE_TIME_BUDGET_SECONDS",
                "Queue time budget",
                45,
                "Soft queue-generation budget, checked between transactions; an atomic target can take longer.",
                "seconds",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_PRIORITY_RETAG_BATCH_SIZE",
                "Priority update batch",
                1000,
                "Maximum queued jobs updated per profile and pass after its priority changes.",
                "jobs",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_ORPHAN_SWEEP_INTERVAL_SECONDS",
                "Orphan repair interval",
                900,
                "Minimum interval between orphan working-state repairs.",
                "seconds",
                minimum=1,
            ),
            Setting(
                "SCHEDULER_ORPHAN_SWEEP_BATCH_SIZE",
                "Orphan repair batch",
                2000,
                "Maximum orphan target/profile states repaired per sweep.",
                "states",
                minimum=1,
            ),
        ),
    ),
    Section(
        "Background indexing",
        "Tune automatic rule reconciliation and its protection of search performance. Changes do "
        "not restart a running job when saved.",
        "Web application, scheduler and indexing worker",
        (
            Setting(
                "TAG_RECONCILIATION_ENABLED",
                "Enable automatic indexing",
                True,
                "Allow the scheduler to supervise the reconciliation worker.",
            ),
            Setting(
                "TAG_RECONCILIATION_POLL_SECONDS",
                "Supervision interval",
                30,
                "Interval between scheduler checks for rule changes and worker state.",
                "seconds",
                minimum=1,
            ),
            Setting(
                "TAG_RECONCILIATION_BATCH_SIZE",
                "Processing batch size",
                25,
                "Documents processed per worker batch.",
                "documents",
                minimum=1,
            ),
            Setting(
                "TAG_RECONCILIATION_PAUSE_SECONDS",
                "Batch pause",
                0.1,
                "Pause between processing batches; zero disables this fixed pause.",
                "seconds",
                minimum=0,
            ),
            Setting(
                "TAG_RECONCILIATION_PLANNING_BATCH_SIZE",
                "Maximum planning batch",
                1000,
                "Upper bound for adaptive inventory reads.",
                "entries",
                minimum=1,
            ),
            Setting(
                "TAG_RECONCILIATION_MIN_PLANNING_BATCH_SIZE",
                "Minimum planning batch",
                25,
                "Lower bound for adaptive inventory reads; cannot exceed the maximum.",
                "entries",
                minimum=1,
            ),
            Setting(
                "TAG_RECONCILIATION_LATENCY_BUDGET",
                "Search slowdown target",
                0.10,
                "Fractional target: 0.10 means +10%. This is adaptive feedback, not a latency guarantee.",
                "fraction",
                minimum=0,
            ),
            Setting(
                "TAG_RECONCILIATION_QUIET_SECONDS",
                "Quiet period",
                2,
                "Minimum quiet time after foreground activity before indexing resumes.",
                "seconds",
                kind="float",
                minimum=0,
            ),
            Setting(
                "TAG_RECONCILIATION_IDLE_SECONDS",
                "Idle acceleration delay",
                15,
                "Quiet time before full-speed indexing; cannot be shorter than the quiet period.",
                "seconds",
                kind="float",
                minimum=0,
            ),
            Setting(
                "TAG_RECONCILIATION_UNIT_SECONDS",
                "Planning duration target",
                0.05,
                "Soft duration target for each planning read; running commands cannot be interrupted.",
                "seconds",
                minimum=0.001,
            ),
        ),
    ),
    Section(
        "Storage and retention",
        "Choose data directories and retention periods. Changing a directory does not move "
        "existing files; migrate them before restarting.",
        "Web application and scheduler",
        (
            Setting(
                "JSON_FOLDER",
                "Scan result directory",
                "{webapp}/app/jsons",
                "Directory containing sharded scan result JSON files.",
                kind="path",
            ),
            Setting(
                "EXPORT_JOBS_FOLDER",
                "Search export directory",
                "{webapp}/app/export_jobs",
                "Directory for asynchronous search export files.",
                kind="path",
            ),
            Setting(
                "EXPORT_JOBS_RETENTION_DAYS",
                "Export retention",
                10,
                "Generated exports older than this are removed by the next cleanup after restart.",
                "days",
                minimum=1,
            ),
            Setting(
                "JOB_SCAVENGE",
                "Job retention",
                60,
                "Finished job records and their local files become eligible for scheduler cleanup after this age.",
                "days",
                minimum=1,
            ),
        ),
    ),
    Section(
        "Search, reports and domain parsing",
        "Configure search sessions, report history and additional private domain suffixes.",
        "Web application, scheduler and indexing worker for domain parsing",
        (
            Setting(
                "SEARCH_SESSION_TTL_SECONDS",
                "Search session lifetime",
                3600,
                "Retention of in-memory pagination sessions.",
                "seconds",
                minimum=1,
            ),
            Setting(
                "REPORT_PTR_LAST_SEEN_MONTHS",
                "Report PTR history",
                6,
                "Include PTR hostnames only from source documents seen within this many months of the report end.",
                "months",
                minimum=1,
            ),
            Setting(
                "TLDADD",
                "Additional private suffixes",
                ("local",),
                "One suffix per line. Changing parsing rules can trigger automatic reparsing after restart.",
                kind="suffixes",
            ),
        ),
    ),
    Section(
        "Logging",
        "Set console verbosity and optional application log files, rotated daily at local midnight.",
        "Web application and indexing worker",
        (
            Setting(
                "LOG_LEVEL",
                "Log level",
                "WARNING",
                "Minimum severity sent to application log handlers.",
                kind="level",
            ),
            Setting(
                "LOG_ENABLED",
                "Enable file logging",
                False,
                "Write persistent logs in addition to console output.",
            ),
            Setting(
                "LOG_DIR",
                "Log directory",
                "./log",
                "Destination directory for date-named log files.",
                kind="path",
            ),
            Setting(
                "LOG_FILE_PREFIX",
                "Log filename prefix",
                "island",
                "Prefix for files named <prefix>-YYMMDD.log; use letters, digits, dots, underscores or hyphens.",
                kind="prefix",
            ),
            Setting(
                "LOG_ROTATION_DAYS",
                "Legacy rotation interval",
                1,
                "Inactive compatibility setting: files always rotate daily at local midnight.",
                "days",
                inactive=True,
            ),
            Setting(
                "LOG_RETENTION_DAYS",
                "Log retention",
                90,
                "Older matching log files become eligible for deletion after restart.",
                "days",
                minimum=1,
            ),
        ),
    ),
)
SETTINGS = {field.key: field for section in SECTIONS for field in section.fields}


def default_value(field, webapp_dir):
    """Resolve path defaults without evaluating Python configuration source."""
    if field.kind == "suffixes":
        return list(field.default)
    if field.kind == "path":
        return field.default.replace("{webapp}", str(webapp_dir))
    return field.default


def validate_host(value):
    """Accept hostnames and IPv4/IPv6 addresses, including internal services."""
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if len(value) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in value.rstrip(".").split(".")
    ):
        raise ValueError


def validate_sender(value):
    """Accept a plain RFC mailbox without ambiguous routing or header syntax."""
    if any(char in value for char in '\r\n()![]:%"') or "=?" in value:
        raise ValueError
    local, _, domain = value.rpartition("@")
    if "." not in domain or "xn--" in domain.lower():
        raise ValueError
    if len(local) > 64 or len(domain) > 255 or len(value) > 320:
        raise ValueError
    validate_email(value, check_deliverability=False, allow_smtputf8=False)


def parse_value(field, value):
    """Validate a field and report only its trusted key on failure."""
    try:
        return _parse_value(field, value)
    except (ValueError, TypeError, OverflowError, EmailNotValidError):
        raise SettingsError(
            f"{field.key}: enter a valid {field.value_type} value."
        ) from None


def _parse_number(field, value):
    """Keep booleans, non-finite numbers and unsupported ranges out of settings."""
    kind = field.value_type
    if isinstance(value, bool):
        raise ValueError
    if kind != "float" and not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError
    number = float(value) if kind == "float" else int(value)
    if not math.isfinite(number) or (
        field.minimum is not None and number < field.minimum
    ):
        raise ValueError
    if kind == "port" and not 1 <= number <= 65535:
        raise ValueError
    if field.key == "SCHEDULER_QUEUE_STATE_BATCH_SIZE" and number > 256:
        raise ValueError
    return number


def _parse_suffixes(value):
    """Normalize a declared suffix list without silently dropping invalid items."""
    values = value.splitlines() if isinstance(value, str) else value
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(item, str) for item in values
    ):
        raise ValueError
    suffixes = sorted(
        {item.strip().lower().lstrip(".") for item in values if item.strip()}
    )
    for suffix in suffixes:
        validate_host(suffix)
    return suffixes


def _validate_url(value):
    """Accept backend HTTP URLs, with credentials supplied separately."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError
    validate_host(parsed.hostname)
    _ = parsed.port
    if any(char.isspace() for char in value):
        raise ValueError


def _validate_text(kind, value):
    """Validate the remaining declarative text controls."""
    if kind == "host":
        validate_host(value)
    elif kind == "url":
        _validate_url(value)
    elif kind == "email":
        validate_sender(value)
    elif kind == "path":
        if any(char in value for char in "\r\n"):
            raise ValueError
        path = Path(value).expanduser()
        if path.exists() and not path.is_dir():
            raise ValueError
    elif kind == "level" and value not in {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }:
        raise ValueError
    elif kind == "prefix" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise ValueError


def _parse_value(field, value):
    kind = field.value_type
    if kind == "bool":
        if value not in ("true", "false") and not isinstance(value, bool):
            raise ValueError
        return value is True or value == "true"
    if kind in {"int", "port", "float"}:
        return _parse_number(field, value)
    if kind == "suffixes":
        return _parse_suffixes(value)
    if not isinstance(value, str) or "\0" in value:
        raise ValueError
    value = value if field.secret else value.strip()
    if not value:
        if field.optional:
            return ""
        raise ValueError
    if field.secret:
        if value == "YouNeedToChangeMeInProduction":
            raise ValueError
    else:
        _validate_text(kind, value)
    return value


def validate_dependencies(values):
    """Reject incompatible options before any configuration is written."""
    if values.get("REPORT_SMTP_USE_TLS") and values.get("REPORT_SMTP_USE_SSL"):
        raise SettingsError("Choose either STARTTLS or implicit TLS, not both.")
    for low, high in (
        (
            "TAG_RECONCILIATION_MIN_PLANNING_BATCH_SIZE",
            "TAG_RECONCILIATION_PLANNING_BATCH_SIZE",
        ),
        ("TAG_RECONCILIATION_QUIET_SECONDS", "TAG_RECONCILIATION_IDLE_SECONDS"),
    ):
        if float(values[low]) > float(values[high]):
            raise SettingsError(f"{low} must not exceed {high}.")
