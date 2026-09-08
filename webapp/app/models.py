"""
.-..-. .--. .---.  .--. .-.
: `' :: ,. :: .  :: .--': :
: .. :: :: :: :: :: `;  : :    .--.
: :; :: :; :: :; :: :__ : :__ `._-.'
:_;:_;`.__.':___.'`.__.':___.'`.__.'

This is the module containing all the data models
"""

import html
import re
import shlex
from flask_appbuilder import Model
from markupsafe import Markup as Esc
from sqlalchemy import (
    BigInteger,
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Table,
    Text,
    UniqueConstraint,
)
from flask_appbuilder.models.mixins import FileColumn
from sqlalchemy import func
from sqlalchemy.orm import relationship, object_session, validates
from .utils.mutils import compute_scan_unit_count
from .utils.timeutils import utcnow_naive

NMAP_ADDITIONAL_PARAMS_MAX_LENGTH = 4096
NMAP_ADDITIONAL_PARAMS_FORBIDDEN_CHARS = frozenset(";&|$" + chr(96) + "<>")

HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")


def is_valid_http_header_name(value):
    """
    Validate a canonical lowercase HTTP header field name.
    """
    header_name = str(value or "").strip()
    return (
        bool(header_name)
        and len(header_name) <= 128
        and bool(HTTP_HEADER_NAME_RE.fullmatch(header_name))
    )


def validate_nmap_additional_params(value):
    """
    Validate optional Nmap parameters as shell-free argv input.

    The agent must receive arguments, never a shell command. Shell control
    characters are rejected here as an early server-side safety check.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Nmap additional params must be a string")

    params = value.strip()
    if not params:
        return None
    if len(params) > NMAP_ADDITIONAL_PARAMS_MAX_LENGTH:
        raise ValueError("Nmap additional params are too long")
    if any(char in params for char in NMAP_ADDITIONAL_PARAMS_FORBIDDEN_CHARS):
        raise ValueError("Nmap additional params contain forbidden shell syntax")
    if "\n" in params or "\r" in params:
        raise ValueError("Nmap additional params must be one line")

    try:
        tokens = shlex.split(params, posix=True)
    except ValueError as error:
        raise ValueError("Nmap additional params must be valid argv syntax") from error
    if not tokens:
        return None
    if any(
        any(char in token for char in NMAP_ADDITIONAL_PARAMS_FORBIDDEN_CHARS)
        for token in tokens
    ):
        raise ValueError("Nmap additional params contain forbidden shell syntax")
    return params


def _html_escape(value, quote=True):
    """
    Escape dynamic content before returning Markup/Esc helper HTML.
    """
    return html.escape("" if value is None else str(value), quote=quote)


class ApiKeys(Model):
    """
    Class for the key authorisation for BOTS
    """

    __tablename__ = "apikeys"
    id = Column(Integer, primary_key=True)
    # It will Will stored as scrypt.
    # The 16 first byte for identify id will be keypt in clear
    # The last 64 are unkfnown and hashed in scrypt
    keyidx = Column(String(16), unique=True, nullable=False)
    key = Column(String(256), unique=True, nullable=False)
    description = Column(String(128), nullable=False)


class Bots(Model):
    """
    Classes for the scannings bots data
    """

    __tablename__ = "bots"
    id = Column(Integer, primary_key=True)
    uid = Column(String(36), unique=True, nullable=False)  # Bot UUID Generate
    ip = Column(String(150), nullable=False)  # Last Bot IP
    country = Column(String(150), nullable=False)  # Last Bot Geoloc
    active = Column(Boolean, default=True)  # This bot is active
    running = Column(Boolean, default=False)  # This bot is currently Scanning
    last_seen = Column(DateTime, default=utcnow_naive)  # Last Bot connection
    device_model = Column(String(128), nullable=False)  # Python Version
    agent_version = Column(String(128), nullable=False)
    system_version = Column(String(128), nullable=False)


# Job to Target pivot table
assoc_jobs_targets = Table(
    "jobs_targets_assoc",
    Model.metadata,
    Column("job_id", Integer, ForeignKey("jobs.id")),
    Column("target_id", Integer, ForeignKey("targets.id")),
)


# ScanProfiles to Ports pivot table
assoc_scanprofiles_ports = Table(
    "scanprofiles_ports_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("scanprofiles.id")),
    Column("port_id", Integer, ForeignKey("ports.id")),
)


# ScanProfiles to Nses scripts pivot table
assoc_scanprofiles_nses = Table(
    "scanprofiles_nses_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("scanprofiles.id")),
    Column("nses_id", Integer, ForeignKey("nses.id")),
)

# ScanProfiles to Targets pivot table
assoc_scanprofiles_targets = Table(
    "scanprofiles_targets_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("scanprofiles.id")),
    Column("target_id", Integer, ForeignKey("targets.id")),
)


class Jobs(Model):
    """
    Class for the Job to be run by bots.

    A Job has one or many Targets.
    """

    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True)
    uid = Column(String(36), unique=True, nullable=False)  # Bot UUID Generate
    job = Column(String, nullable=False)  # Target Bundles (list of str)
    bot_id = Column(Integer)  # Bot currently or lastly on the job
    active = Column(Boolean, default=False)  # Job is running
    finished = Column(Boolean, default=False)  # True if Job was successfull
    exported = Column(Boolean, default=False)  # True if result was exported
    meili_task_uid = Column(Integer, nullable=True)
    meili_documents_submitted = Column(Integer, default=0, nullable=False)
    meili_documents_total = Column(Integer, nullable=True)
    job_end = Column(DateTime, default=None)  # Last job termination.
    job_start = Column(DateTime, default=None)  # Last job Start time
    job_creation = Column(DateTime, default=utcnow_naive)  # Timestamp of job creation
    priority = Column(Integer, default=0)  # Priority, by default LOW
    scanprofile_id = Column(Integer, ForeignKey("scanprofiles.id"), nullable=True)
    scanprofile_cycle_id = Column(
        Integer, ForeignKey("scanprofile_cycles.id"), nullable=True
    )
    scanprofile_name = Column(String(256), nullable=True)
    scan_unit_count = Column(BigInteger, default=1, nullable=False)
    scan_ports = Column(Text, nullable=True)
    scan_nses = Column(Text, nullable=True)
    nmap_additional_params = Column(Text, nullable=True)
    scanprofile = relationship("ScanProfiles", back_populates="jobs")
    scanprofile_cycle = relationship("ScanProfileCycles", back_populates="jobs")
    targets = relationship(
        "Targets", secondary=assoc_jobs_targets, back_populates="jobs"
    )

    @validates("priority")
    def validate_priority(self, key, value):
        """
        Restrict job priority to the five supported queues: 0, 1, 2, 3, 4.
        """
        if value is None:
            return 0
        value = int(value)
        if value < 0 or value > 4:
            raise ValueError("Priority must be between 0 and 4")
        return value

    def __repr__(self):
        return self.job

    def job_html(self):
        """
        Display Range as HTML Tags
        """
        tags = []
        # Render nice html pills
        html = ""
        # Get all tag name for attached groups
        if self.job:
            for tag in self.job.split(","):
                if tag.endswith("/32"):
                    tag = tag[0:-3]
                if tag.endswith("/128"):
                    tag = tag[0:-4]
                tags.append(tag)
        for tag in tags:
            html += f'<span class="label label-default">{_html_escape(tag)}</span> '
        return Esc(html)

    @staticmethod
    def _render_compact_badges(values, limit=4, label_class="label-default"):
        """
        Render a compact badge list with an overflow indicator.
        """
        values = [str(value) for value in values if str(value).strip()]
        if not values:
            return Esc("")

        html = ""
        safe_label_class = _html_escape(label_class)
        for value in values[:limit]:
            html += (
                f'<span class="label {safe_label_class}">'
                f"{_html_escape(value)}</span> "
            )

        remaining = len(values) - limit
        if remaining > 0:
            html += (
                f'<span class="label label-info">+{remaining} more '
                f"({len(values)} total)</span>"
            )

        return Esc(html)

    def job_summary_html(self):
        """
        Compact list-friendly rendering of scan items.
        """
        tags = []
        if self.job:
            for tag in self.job.split(","):
                if tag.endswith("/32"):
                    tag = tag[0:-3]
                if tag.endswith("/128"):
                    tag = tag[0:-4]
                tags.append(tag)
        return self._render_compact_badges(tags)

    def targets_html(self):
        """
        Display Targets as HTML Tags
        """
        tags = []
        # Render nice html pills
        html = ""
        # Get all tag name for attached groups
        if self.targets:
            for tag in self.targets:
                tags.append(tag)
        for tag in tags:
            html += f'<span class="label label-default">{_html_escape(tag)}</span> '
        return Esc(html)

    def targets_count_html(self):
        """
        Compact list-friendly rendering of linked target count.
        """
        session = object_session(self)
        target_count = None
        if session is not None and self.id is not None:
            target_count = (
                session.query(func.count(assoc_jobs_targets.c.target_id))
                .filter(assoc_jobs_targets.c.job_id == self.id)
                .scalar()
            )
        elif self.targets is not None:
            target_count = len(self.targets)

        if not target_count:
            return Esc('<span class="label label-default">0 targets</span>')
        return Esc(
            f'<span class="label label-default">{target_count} target'
            f'{"s" if target_count != 1 else ""}</span>'
        )

    def scan_ports_html(self):
        """
        Display Nmap port list as HTML Tags
        """
        html = ""
        if self.scan_ports:
            for port in self.scan_ports.split(","):
                html += f'<span class="label label-info">{_html_escape(port)}</span> '
        return Esc(html)

    def scan_nses_html(self):
        """
        Display NSE names as HTML Tags
        """
        html = ""
        if self.scan_nses:
            for nse in self.scan_nses.split(","):
                html += f'<span class="label label-primary">{_html_escape(nse)}</span> '
        return Esc(html)

    def scanprofile_label_html(self):
        """
        Render stable scan profile name for job history.

        The FK gives the current profile name when the profile still exists.
        `scanprofile_name` keeps a creation-time snapshot so old jobs remain
        understandable after a profile rename/delete or legacy FK loss.
        """
        if self.scanprofile is not None:
            label = self.scanprofile.name
            title = "current scan profile"
            label_class = "label-default"
        elif (
            self.scanprofile_cycle is not None
            and self.scanprofile_cycle.scanprofile is not None
        ):
            label = self.scanprofile_cycle.scanprofile.name
            title = "scan profile resolved from cycle"
            label_class = "label-info"
        elif self.scanprofile_name:
            label = self.scanprofile_name
            title = "snapshot; current scan profile is missing"
            label_class = "label-warning"
        elif self.scanprofile_id:
            label = f"profile #{self.scanprofile_id}"
            title = "scan profile id without loaded profile"
            label_class = "label-warning"
        else:
            label = "unknown scan profile"
            title = "legacy job without scan profile reference"
            label_class = "label-warning"

        return Esc(
            f'<span class="label {label_class}" title="{_html_escape(title)}">'
            f"{_html_escape(label)}</span>"
        )

    def duration_html(self):
        """
        Compute duration.
        """
        if self.job_start and self.job_end:
            diff = self.job_end - self.job_start
            seconds = diff.total_seconds()
            minutes, seconds = divmod(seconds, 60)

            if minutes == 0:
                return f"{int(seconds)}s"
            else:
                return f"{int(minutes):02d}:{int(seconds):02d}"
        else:
            return "oo"


class Protos(Model):
    """
    Class for the Protocols
        IE : UDP/TCP
    """

    __tablename__ = "protos"
    id = Column(Integer, primary_key=True)
    value = Column(String(32), unique=True, nullable=False)  # Udp / Tcp
    name = Column(String(256), nullable=False)  # Description of the Layer 4 protocol

    def __repr__(self):
        return self.value


class Ports(Model):
    """
    Class for the Ports
    Ports have exactly one mandatory record of Protos
    """

    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    value = Column(Integer, nullable=False)  # Port to Scan
    name = Column(String(256), nullable=False)  # Description of the port
    proto_id = Column(Integer, ForeignKey("protos.id"), nullable=False)
    proto = relationship("Protos", backref="ports")
    proto_to_port = Column(
        String(32 + 5), nullable=False, unique=True
    )  # (str(port.value):str(proto.id)), empeche les doubles tuple port/proto

    def __repr__(self):
        return f"{self.proto}:{self.value}"


class Nses(Model):
    """
    Class for the nsescript
    """

    __tablename__ = "nses"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), unique=True, nullable=False)  # Name of the NSE Script
    hash = Column(String(64), unique=True, nullable=False)  # SHA256 of the NSE Body
    filebody = Column(FileColumn, nullable=False)

    def __repr__(self):
        return self.name


DEFAULT_COLLECTED_HEADERS = (
    "cache-control",
    "clear-site-data",
    "content-type",
    "content-security-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-dns-prefetch-control",
    "x-frame-options",
    "x-permitted-cross-domain-policies",
    "$wsep",
    "host-header",
    "k-proxy-request",
    "liferay-portal",
    "oraclecommercecloud-version",
    "pega-host",
    "powered-by",
    "product",
    "sourcemap",
    "www-authenticate",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-atmosphere-error",
    "x-atmosphere-first-request",
    "x-atmosphere-tracking-id",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-spanid",
    "x-b3-traceid",
    "x-beserver",
    "x-backside-transport",
    "x-cf-powered-by",
    "x-cms",
    "x-calculatedbetarget",
    "x-cocoon-version",
    "x-content-encoded-by",
    "x-diaginfo",
    "x-envoy-attempt-count",
    "x-envoy-external-address",
    "x-envoy-internal",
    "x-envoy-original-dst-host",
    "x-envoy-upstream-service-time",
    "x-feserver",
    "x-framework",
    "x-generated-by",
    "x-generator",
    "x-gitlab-meta",
    "x-jitsi-release",
    "x-joomla-version",
    "x-kubernetes-pf-flowschema-ui",
    "x-kubernetes-pf-prioritylevel-uid",
    "x-kong-proxy-latency",
    "x-kong-upstream-latency",
    "x-kong-response-latency",
    "x-kong-admin-latency",
    "x-kong-upstream-status",
    "x-kong-request-id",
    "x-kong-total-latency",
    "x-kong-third-party-latency",
    "x-kong-client-latency",
    "x-litespeed-cache",
    "x-litespeed-purge",
    "x-litespeed-tag",
    "x-litespeed-vary",
    "x-litespeed-cache-control",
    "x-mod-pagespeed",
    "x-nextjs-cache",
    "x-nextjs-matched-path",
    "x-nextjs-page",
    "x-nextjs-redirect",
    "x-owa-version",
    "x-old-content-length",
    "x-oneagent-js-injection",
    "x-page-speed",
    "x-php-version",
    "x-powered-by",
    "x-powered-by-plesk",
    "x-powered-cms",
    "x-redirect-by",
    "x-server-powered-by",
    "x-sourcefiles",
    "x-sourcemap",
    "x-turbo-charged-by",
    "x-umbraco-version",
    "x-varnish-backend",
    "x-varnish-server",
    "x-woodpecker-version",
    "x-dtagentid",
    "x-dthealthcheck",
    "x-dtinjectedservlet",
    "x-ruxit-js-agent",
)

DEFAULT_VALUE_COLLECTED_HEADERS = frozenset(
    {
        "x-powered-by",
        "x-server-powered-by",
        "powered-by",
        "product",
        "x-generator",
        "x-generated-by",
        "x-powered-cms",
        "x-varnish-backend",
        "x-varnish-server",
        "x-cms",
        "x-framework",
        "x-redirect-by",
        "x-turbo-charged-by",
        "liferay-portal",
        "x-content-encoded-by",
        "x-cf-powered-by",
        "x-owa-version",
        "x-cocoon-version",
        "x-jitsi-release",
        "oraclecommercecloud-version",
        "x-woodpecker-version",
        "x-joomla-version",
        "x-umbraco-version",
        "x-php-version",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "content-type",
        "www-authenticate",
    }
)


class CollectedHeaders(Model):
    """
    Curated HTTP headers indexed from the Nmap http-headers NSE output.
    """

    __tablename__ = "collected_headers"
    id = Column(Integer, primary_key=True)
    header_name = Column(String(128), unique=True, nullable=False)
    collect_value = Column(Boolean, default=False, nullable=False)

    @validates("header_name")
    def validate_header_name(self, _key, value):
        """
        Store HTTP header names in their search/index canonical lowercase form.
        """
        header_name = str(value or "").strip().lower()
        if not is_valid_http_header_name(header_name):
            raise ValueError("Header name must be a valid HTTP field name")
        return header_name

    def __repr__(self):
        return self.header_name


def ensure_default_collected_headers(session):
    """
    Seed fresh installs with the curated HTTP header collection defaults.
    """
    existing = {
        row.header_name: row
        for row in session.query(CollectedHeaders)
        .filter(CollectedHeaders.header_name.in_(DEFAULT_COLLECTED_HEADERS))
        .all()
    }
    changed = False

    for header_name in DEFAULT_COLLECTED_HEADERS:
        collect_value = header_name in DEFAULT_VALUE_COLLECTED_HEADERS
        row = existing.get(header_name)
        if row is None:
            session.add(
                CollectedHeaders(
                    header_name=header_name,
                    collect_value=collect_value,
                )
            )
            changed = True
            continue
        if collect_value and not row.collect_value:
            row.collect_value = True
            changed = True

    if changed:
        session.commit()


TAG_RULE_HEADER_RE = re.compile(
    r"\b(http_header|http_headval)(?:\.[a-z]+)?\s*:\s*"
    r"([!#$%&'*+\-.^_`|~0-9a-z]+)",
    re.IGNORECASE,
)


def headers_required_by_tag_rules(rules):
    """Return collected header names and value flags required by tag rules."""
    from .utils.tagrules import analyze_header_dependencies

    required = {}
    for rule in rules or []:
        if isinstance(rule, dict):
            criteria_groups = rule.get("criteria_groups")
            query = str(rule.get("query", "") or "")
        else:
            criteria_groups = getattr(rule, "criteria_groups", None)
            query = str(getattr(rule, "query", "") or "")
        if criteria_groups is None:
            for field, header_name in TAG_RULE_HEADER_RE.findall(query):
                header_name = header_name.strip().lower()
                if is_valid_http_header_name(header_name):
                    required[header_name] = required.get(header_name, False) or field.lower() == "http_headval"
            continue
        for header_name, collect_value in analyze_header_dependencies(
            criteria_groups
        )["exact"].items():
            required[header_name] = required.get(header_name, False) or collect_value
    return required


def ensure_rule_required_headers(session, compiled_rules=None, commit=True):
    """Ensure headers referenced by active tag rules are indexed."""
    active_rules = session.query(TagRules).filter(TagRules.active == True).all()
    if compiled_rules is None:
        from .utils.tagrules import compile_tag_rule_records

        compiled_rules = compile_tag_rule_records(active_rules)
    required = headers_required_by_tag_rules(compiled_rules)
    summary = {
        "enabled_presence": [],
        "enabled_values": [],
        "cleanup_candidates": [],
        "ambiguous": [],
    }
    from .utils.tagrules import analyze_header_dependencies

    for rule in compiled_rules:
        summary["ambiguous"].extend(
            analyze_header_dependencies(rule.get("criteria_groups", [])).get(
                "ambiguous", []
            )
        )
    summary["ambiguous"] = sorted(set(summary["ambiguous"]))
    if not required:
        return summary

    existing = {
        row.header_name: row
        for row in session.query(CollectedHeaders)
        .filter(CollectedHeaders.header_name.in_(required))
        .all()
    }
    changed = False
    for header_name, collect_value in required.items():
        row = existing.get(header_name)
        if row is None:
            session.add(
                CollectedHeaders(
                    header_name=header_name,
                    collect_value=collect_value,
                )
            )
            changed = True
            summary["enabled_presence"].append(header_name)
            if collect_value:
                summary["enabled_values"].append(header_name)
        elif collect_value and not row.collect_value:
            row.collect_value = True
            changed = True
            summary["enabled_values"].append(header_name)
    defaults = set(DEFAULT_COLLECTED_HEADERS)
    summary["cleanup_candidates"] = sorted(
        row.header_name
        for row in session.query(CollectedHeaders).all()
        if row.header_name not in required and row.header_name not in defaults
    )
    if changed and commit:
        session.commit()
    return summary


class TagRules(Model):
    """
    Search-backed tagging rules applied on parsed search documents.
    """

    __tablename__ = "tagrules"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), unique=True, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    description = Column(String(512), nullable=False)
    query = Column(Text, nullable=False)
    tags = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, default=utcnow_naive, nullable=False)
    updated_at = Column(
        DateTime,
        default=utcnow_naive,
        onupdate=utcnow_naive,
        nullable=False,
    )

    def __repr__(self):
        return self.name

    def tags_list(self):
        """
        Return stored tags as a Python list.
        """
        values = []
        for line in str(self.tags or "").replace(",", "\n").splitlines():
            value = str(line).strip()
            if value:
                values.append(value)
        return values

    def tags_html(self):
        """
        Display tags as compact HTML badges.
        """
        tags = self.tags_list()
        if not tags:
            return Esc("")

        visible_limit = 2
        title = _html_escape(", ".join(tags), quote=True)
        rendered = ""
        rendered += f'<span class="tagrules-tags" title="{title}">'
        for tag in tags[:visible_limit]:
            rendered += (
                '<span class="label label-default tagrules-tag">'
                f"{_html_escape(tag)}"
                "</span> "
            )

        remaining = len(tags) - visible_limit
        if remaining > 0:
            rendered += (
                '<span class="label label-info tagrules-tag">' f"+{remaining}" "</span>"
            )
        rendered += "</span>"
        return Esc(rendered)

    def name_html(self):
        """
        Render the rule name with the description available on hover.
        """
        name = _html_escape(self.name)
        description = _html_escape(self.description, quote=True)
        if not description:
            return Esc(name)
        return Esc(f'<span title="{description}">{name}</span>')

    def active_html(self):
        """
        Compact list-friendly active state indicator.
        """
        if self.active:
            return Esc('<i class="fa fa-check text-success" title="Active"></i>')
        return Esc('<i class="fa fa-times text-muted" title="Inactive"></i>')

    @staticmethod
    def _datetime_html(value):
        """
        Render datetimes without microseconds for compact UI tables.
        """
        if not value:
            return Esc("")
        if hasattr(value, "strftime"):
            return Esc(value.strftime("%Y-%m-%d %H:%M:%S"))
        return Esc(_html_escape(str(value).split(".", 1)[0]))

    def created_at_html(self):
        return self._datetime_html(self.created_at)

    def updated_at_html(self):
        return self._datetime_html(self.updated_at)


class Reports(Model):
    """
    Scheduled Markdown reports backed by KVrocks search queries.
    """

    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), unique=True, nullable=False)
    active = Column(Boolean, default=False, nullable=False)
    description = Column(Text, nullable=False, default="")
    query = Column(Text, nullable=False)
    emails = Column(Text, nullable=False, default="")
    schedule_type = Column(String(32), nullable=False, default="monthly")
    schedule_day = Column(Integer, nullable=False, default=1)
    schedule_hour = Column(Integer, nullable=False, default=8)
    last_run_at = Column(DateTime, default=None)
    next_run_at = Column(DateTime, default=None)
    created_at = Column(DateTime, default=utcnow_naive, nullable=False)
    updated_at = Column(
        DateTime,
        default=utcnow_naive,
        onupdate=utcnow_naive,
        nullable=False,
    )

    def __repr__(self):
        return self.name

    def emails_list(self):
        """
        Return stored reporting emails as a Python list.
        """
        values = []
        seen = set()
        for line in str(self.emails or "").replace(",", "\n").splitlines():
            value = str(line).strip().lower()
            if not value or value in seen:
                continue
            seen.add(value)
            values.append(value)
        return values

    def emails_html(self):
        """
        Display reporting emails as HTML badges.
        """
        html = ""
        for email in self.emails_list():
            html += f'<span class="label label-default">{_html_escape(email)}</span> '
        return Esc(html)

    def schedule_html(self):
        """
        Display the configured reporting schedule.
        """
        if self.schedule_type == "monthly":
            schedule_day = int(self.schedule_day or 0)
            schedule_hour = int(self.schedule_hour or 0)
            return Esc(
                f'<span class="label label-info">monthly day '
                f"{schedule_day:02d} at {schedule_hour:02d}:00</span>"
            )
        return Esc(
            f'<span class="label label-default">'
            f"{_html_escape(self.schedule_type)}</span>"
        )

    def actions_html(self):
        """
        Render report-specific actions.
        """
        if not self.id:
            return Esc("")
        return Esc(
            f'<a class="btn btn-sm btn-default" href="/reportsview/preview_loading/{self.id}">'
            "Preview</a> "
            f'<a class="btn btn-sm btn-primary" href="/reportsview/run/{self.id}">'
            "Run now</a>"
        )


class TargetScanStates(Model):
    """
    Runtime state of one ScanProfile applied to one Target.
    """

    __tablename__ = "target_scan_states"
    __table_args__ = (
        UniqueConstraint(
            "target_id",
            "scanprofile_id",
            name="uq_target_scan_states_target_profile",
        ),
    )

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scanprofile_id = Column(Integer, ForeignKey("scanprofiles.id"), nullable=False)
    working = Column(Boolean, default=False)
    last_scan = Column(DateTime, default=None)
    last_previous_scan = Column(DateTime, default=None)

    target = relationship("Targets", back_populates="scan_states")
    scanprofile = relationship("ScanProfiles", back_populates="scan_states")

    def __repr__(self):
        return f"{self.target} :: {self.scanprofile}"

    def duration_html(self):
        """
        Compute cycle duration for this target/profile pair.
        """
        if self.last_scan and self.last_previous_scan:
            diff = self.last_scan - self.last_previous_scan
            total_seconds = int(diff.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            if hours:
                return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            elif minutes:
                return f"{minutes:02d}:{seconds:02d}"
            else:
                return f"{seconds}s"
        return "∞"


class ScanProfileCycles(Model):
    """
    Runtime cycle state for one scan profile.

    A cycle starts when the scheduler creates queued jobs for a scan profile.
    It finishes only when every currently applicable target/profile state has
    been scanned after `started_at` and no unfinished job remains for the
    profile. This makes cycle completion recoverable after restart and
    independent from old deleted job rows.
    """

    __tablename__ = "scanprofile_cycles"

    id = Column(Integer, primary_key=True)
    scanprofile_id = Column(Integer, ForeignKey("scanprofiles.id"), nullable=False)
    started_at = Column(DateTime, default=utcnow_naive, nullable=False)
    finished_at = Column(DateTime, default=None)
    status = Column(String(32), default="running", nullable=False)
    target_count = Column(Integer, default=0, nullable=False)
    completed_target_count = Column(Integer, default=0, nullable=False)
    scan_unit_count = Column(BigInteger, default=0, nullable=False)
    completed_scan_unit_count = Column(BigInteger, default=0, nullable=False)
    max_target_id = Column(Integer, default=None)

    scanprofile = relationship(
        "ScanProfiles",
        foreign_keys=[scanprofile_id],
        back_populates="cycles",
    )
    jobs = relationship("Jobs", back_populates="scanprofile_cycle")

    def __repr__(self):
        if self.scanprofile is not None:
            return f"{self.scanprofile} cycle {self.id}"
        return f"cycle {self.id}"

    @staticmethod
    def _format_duration(started_at, finished_at=None):
        """
        Render elapsed cycle time as HH:MM:SS, MM:SS, or seconds.
        """
        if started_at is None:
            return ""
        end_at = finished_at or utcnow_naive()
        total_seconds = max(0, int((end_at - started_at).total_seconds()))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        if minutes:
            return f"{minutes:02d}:{seconds:02d}"
        return f"{seconds}s"

    @staticmethod
    def _format_datetime(value):
        """
        Render compact UTC-naive timestamps used by the legacy UI.
        """
        if value is None:
            return "running"
        return value.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _format_percent(completed, total):
        """
        Render bounded scan-unit progress.
        """
        total = int(total or 0)
        completed = int(completed or 0)
        if total <= 0:
            return 0.0
        return min(100.0, max(0.0, (completed / total) * 100))

    @staticmethod
    def _format_blockers(target_completed, target_total, queued_jobs, active_jobs):
        """
        Render observable reasons why a running cycle cannot finish yet.
        """
        incomplete_targets = max(
            0,
            int(target_total or 0) - int(target_completed or 0),
        )
        blockers = []
        if incomplete_targets:
            blockers.append(f"{incomplete_targets:,} incomplete target")
        if queued_jobs:
            blockers.append(f"{int(queued_jobs):,} queued job")
        if active_jobs:
            blockers.append(f"{int(active_jobs):,} active job")
        return ", ".join(blockers)

    def _job_blocker_counts(self):
        """
        Return queued and active unfinished jobs attached to this cycle.
        """
        session = object_session(self)
        if session is None or self.id is None:
            return 0, 0

        counts = {False: 0, True: 0}
        rows = (
            session.query(Jobs.active, func.count(Jobs.id))
            .filter(
                Jobs.scanprofile_cycle_id == self.id,
                Jobs.finished.is_(False),
            )
            .group_by(Jobs.active)
            .all()
        )
        for active, count in rows:
            counts[bool(active)] = int(count or 0)
        return counts[False], counts[True]

    @staticmethod
    def _progress_title(
        completed,
        total,
        target_completed,
        target_total,
        job_counts=None,
    ):
        """
        Render compact cycle tooltip text.
        """
        queued_jobs, active_jobs = job_counts or (0, 0)
        title = (
            f"{int(completed or 0):,}/{int(total or 0):,} IP scan for "
            f"{int(target_completed or 0):,}/{int(target_total or 0):,} target"
        )
        blockers = ScanProfileCycles._format_blockers(
            target_completed,
            target_total,
            queued_jobs,
            active_jobs,
        )
        if blockers:
            title += f"; blockers: {blockers}"
        return title

    def blocker_summary(self):
        """
        Return current completion blockers for list/show views.
        """
        if self.status != "running":
            return ""
        queued_jobs, active_jobs = self._job_blocker_counts()
        blockers = self._format_blockers(
            self.completed_target_count,
            self.target_count,
            queued_jobs,
            active_jobs,
        )
        return blockers or "reconciliation pending"

    def duration_html(self):
        """
        Current elapsed duration, or final duration after completion.
        """
        return self._format_duration(self.started_at, self.finished_at)

    def status_html(self):
        """
        Render cycle status as a small FAB table badge.
        """
        status = self.status or "running"
        label_class = "label-success" if status == "finished" else "label-info"
        return Esc(f'<span class="label {label_class}">{_html_escape(status)}</span>')

    def list_status_html(self):
        """
        Render cycle status label for the list view.
        """
        status = self.status or "running"
        display_status = "waiting" if status == "finished" else status
        label_class = "label-primary" if display_status == "waiting" else "label-info"
        return Esc(
            f'<span class="label {label_class}">{_html_escape(display_status)}</span>'
        )

    def progress_html(self):
        """
        Render scan-unit completion percentage for this cycle.
        """
        total = int(self.scan_unit_count or 0)
        completed = int(self.completed_scan_unit_count or 0)
        target_total = int(self.target_count or 0)
        target_completed = int(self.completed_target_count or 0)
        queued_jobs, active_jobs = self._job_blocker_counts()
        percent = self._format_percent(completed, total)
        title = self._progress_title(
            completed,
            total,
            target_completed,
            target_total,
            (queued_jobs, active_jobs),
        )
        return Esc(
            '<span class="label label-default" '
            f'title="{_html_escape(title)}">{percent:.1f}%</span>'
        )

    def summary_badge_html(self, label):
        """
        Compact badge used from ScanProfiles list/show pages.
        """
        status = self.status or "running"
        label_class = "label-success" if status == "finished" else "label-info"
        total = int(self.scan_unit_count or 0)
        completed = int(self.completed_scan_unit_count or 0)
        target_total = int(self.target_count or 0)
        target_completed = int(self.completed_target_count or 0)
        queued_jobs, active_jobs = self._job_blocker_counts()
        percent = self._format_percent(completed, total)
        title = self._progress_title(
            completed,
            total,
            target_completed,
            target_total,
            (queued_jobs, active_jobs),
        )
        return (
            f'<span class="label {label_class}" title="{_html_escape(title)}">'
            f"{_html_escape(label)} {percent:.1f}%</span>"
        )

    def previous_cycle_html(self):
        """
        Show the previous cycle for the same scan profile.
        """
        session = object_session(self)
        if session is None or self.id is None or self.scanprofile_id is None:
            return Esc("")

        query = (
            session.query(ScanProfileCycles)
            .filter(
                ScanProfileCycles.scanprofile_id == self.scanprofile_id,
                ScanProfileCycles.id != self.id,
                ScanProfileCycles.status == "finished",
            )
            .order_by(
                ScanProfileCycles.finished_at.desc(),
                ScanProfileCycles.id.desc(),
            )
        )
        if self.started_at is not None:
            query = query.filter(ScanProfileCycles.started_at < self.started_at)

        previous_cycle = query.first()
        if previous_cycle is None:
            return Esc('<span class="label label-default">no previous cycle</span>')

        started_at = self._format_datetime(previous_cycle.started_at)
        finished_at = self._format_datetime(previous_cycle.finished_at)
        duration = previous_cycle.duration_html()
        completed = int(previous_cycle.completed_scan_unit_count or 0)
        total = int(previous_cycle.scan_unit_count or 0)
        percent = self._format_percent(completed, total)
        return Esc(
            '<div class="scan-cycle-previous">'
            f'<span class="label label-success">tour -1 {percent:.1f}%</span> '
            f"<span>start: {_html_escape(started_at)}</span> "
            f"<span>stop: {_html_escape(finished_at)}</span> "
            f"<span>duration: {_html_escape(duration)}</span>"
            "</div>"
        )


class ScanProfiles(Model):
    """
    A Scan profile define for a target range which are the
    Ports to scan
    Nse script to launch
    If the boolean "Default" is set..This profile will be applied to all ranges without assignations.

    A scan profile has;
    One or many Ports objects.
    Zero or many Nses script objects.
    zero or many Targets objects
    """

    __tablename__ = "scanprofiles"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)  # Name of the profile.
    apply_to_all = Column(Boolean, default=False)  # Name of the profile.
    ports = relationship(
        "Ports",
        secondary=assoc_scanprofiles_ports,
        backref="scanprofiles",
    )
    nses = relationship(
        "Nses", secondary=assoc_scanprofiles_nses, backref="scanprofiles"
    )
    targets = relationship(
        "Targets", secondary=assoc_scanprofiles_targets, backref="scanprofiles"
    )

    priority = Column(Integer, default=0)
    priority_retag_pending = Column(Boolean, default=False, nullable=False)
    scan_cycle_minutes = Column(Integer, default=720)
    nmap_additional_params = Column(Text, nullable=True)
    current_cycle_id = Column(Integer, default=None)
    last_cycle_finished_at = Column(DateTime, default=None)
    jobs = relationship("Jobs", back_populates="scanprofile")
    cycles = relationship(
        "ScanProfileCycles",
        foreign_keys="ScanProfileCycles.scanprofile_id",
        back_populates="scanprofile",
        cascade="all, delete-orphan",
    )
    scan_states = relationship(
        "TargetScanStates", back_populates="scanprofile", cascade="all, delete-orphan"
    )

    @validates("nmap_additional_params")
    def validate_nmap_additional_params_field(self, _key, value):
        """Keep stored profile parameters safe for shell-free agents."""
        return validate_nmap_additional_params(value)

    @validates("priority")
    def validate_priority(self, key, value):
        """
        Restrict scan profile priority to the five supported queues: 0, 1, 2, 3, 4.
        """
        if value is None:
            return 0
        value = int(value)
        if value < 0 or value > 4:
            raise ValueError("Priority must be between 0 and 4")
        return value

    def __repr__(self):
        return self.name

    def cycle_summary_html(self):
        """
        Show up to two retained cycles for this profile.
        """
        session = object_session(self)
        if session is None or self.id is None:
            return Esc("")

        rows = []
        running_cycle = None
        if self.current_cycle_id:
            running_cycle = (
                session.query(ScanProfileCycles)
                .filter(
                    ScanProfileCycles.id == self.current_cycle_id,
                    ScanProfileCycles.scanprofile_id == self.id,
                    ScanProfileCycles.status == "running",
                )
                .one_or_none()
            )
        if running_cycle is None:
            running_cycle = (
                session.query(ScanProfileCycles)
                .filter(
                    ScanProfileCycles.scanprofile_id == self.id,
                    ScanProfileCycles.status == "running",
                )
                .order_by(
                    ScanProfileCycles.started_at.desc(), ScanProfileCycles.id.desc()
                )
                .first()
            )
        if running_cycle is not None:
            rows.append(("Current", running_cycle))

        remaining_slots = max(0, 2 - len(rows))
        finished_cycles = (
            session.query(ScanProfileCycles)
            .filter(
                ScanProfileCycles.scanprofile_id == self.id,
                ScanProfileCycles.status == "finished",
            )
            .order_by(
                ScanProfileCycles.finished_at.desc(),
                ScanProfileCycles.id.desc(),
            )
            .limit(remaining_slots)
            .all()
        )
        for index, cycle in enumerate(finished_cycles):
            rows.append(("Last" if index == 0 else "Previous", cycle))

        if not rows:
            return Esc('<span class="label label-default">no cycle</span>')
        return Esc(" ".join(cycle.summary_badge_html(label) for label, cycle in rows))

    def current_cycle_summary_html(self):
        """
        Show only the active running cycle for this profile.
        """
        session = object_session(self)
        if session is None or self.id is None:
            return Esc("")

        running_cycle = None
        if self.current_cycle_id:
            running_cycle = (
                session.query(ScanProfileCycles)
                .filter(
                    ScanProfileCycles.id == self.current_cycle_id,
                    ScanProfileCycles.scanprofile_id == self.id,
                    ScanProfileCycles.status == "running",
                )
                .one_or_none()
            )
        if running_cycle is None:
            running_cycle = (
                session.query(ScanProfileCycles)
                .filter(
                    ScanProfileCycles.scanprofile_id == self.id,
                    ScanProfileCycles.status == "running",
                )
                .order_by(
                    ScanProfileCycles.started_at.desc(), ScanProfileCycles.id.desc()
                )
                .first()
            )

        if running_cycle is None:
            return Esc('<span class="label label-default">no current cycle</span>')
        return Esc(running_cycle.summary_badge_html("Current"))


class Targets(Model):
    """
    Class for networks and hosts targets definitions

    A Targets has one or many Jobs.
    """

    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    value = Column(String(45), unique=True, nullable=False)  # The CIDR or HOST
    description = Column(String(256))  # A facultative descrition
    active = Column(Boolean, default=True)  # To suspend the target
    working = Column(Boolean, default=False)  # Set when jobs todo are presents
    last_scan = Column(DateTime, default=None)  # Last Scan of the Range.
    last_previous_scan = Column(
        DateTime, default=None
    )  # Previous Last Scan to have an idea of time for a cycle.
    jobs = relationship("Jobs", secondary=assoc_jobs_targets, back_populates="targets")
    scan_states = relationship(
        "TargetScanStates", back_populates="target", cascade="all, delete-orphan"
    )

    as_bgp = Column(Integer, default=0)  # BGP AS Number
    as_description = Column(String(256))  # AS Description.
    as_country = Column(String(2), default="ZZ")  # AS Country
    priority = Column(Integer, default=1)  # Priority, by default LOW
    scan_unit_count = Column(BigInteger, default=1, nullable=False)

    @validates("value")
    def validate_value(self, key, value):
        """
        Maintain the precalculated scan-unit count when target value changes.
        """
        self.scan_unit_count = compute_scan_unit_count(value)
        return value

    @validates("priority")
    def validate_priority(self, key, value):
        """
        Restrict target priority metadata to the supported queue range.
        """
        if value is None:
            return 1
        value = int(value)
        if value < 0 or value > 4:
            raise ValueError("Priority must be between 0 and 4")
        return value

    def __repr__(self):
        """
        Nice representation
        """
        return self.value

    def duration_html(self):
        """
        Compute spend time
        """
        if self.last_scan and self.last_previous_scan:
            diff = self.last_scan - self.last_previous_scan
            total_seconds = int(diff.total_seconds())

            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            if hours:
                return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            elif minutes:
                return f"{minutes:02d}:{seconds:02d}"
            else:
                return f"{seconds}s"
        else:
            return "∞"
