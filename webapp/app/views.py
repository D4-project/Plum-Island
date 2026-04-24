"""
 .--. .-..-..-.                     .-.
: .--': :: :: :                     : :
: : _ : :: :: :       .--.  .--.  .-' : .--.
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
"""

import calendar
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import shlex
import threading
import time
import uuid

from flask import render_template, redirect, make_response, send_file, flash, url_for
from flask import request, jsonify
from flask_appbuilder import BaseView
from flask_appbuilder import ModelView, action, has_access
from flask_appbuilder.api import expose
from flask_appbuilder.filemanager import FileManager
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from markupsafe import Markup, escape
from meilisearch import Client
from meilisearch.errors import MeilisearchApiError
import requests

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from wtforms import TextAreaField, SubmitField, Field, ValidationError, IntegerField
from wtforms.validators import Optional, NumberRange
from wtforms.widgets import html_params
from app import app
from .models import (
    Bots,
    Targets,
    Jobs,
    ApiKeys,
    Nses,
    Protos,
    ScanProfiles,
    Ports,
    TargetScanStates,
)
from .utils.mutils import is_valid_uuid, is_valid_ip, is_valid_cidr
from .utils.mutils import is_valid_ip_or_cidr, is_valid_fqdn, lowercase_dict
from .utils.kvrocks import KVrocksIndexer
from .utils.ip2asn import get_asn_description_for_ip
from .utils.timeutils import ensure_utc_naive, utcnow_iso


from . import appbuilder, db

logger = logging.getLogger("flask_appbuilder")
EXPORT_JOB_STATES = {}
EXPORT_JOB_STATES_LOCK = threading.Lock()


def build_priority_field(label="Priority"):
    """
    Shared priority field limited to the three supported queues: 0, 1, 2.
    """
    return IntegerField(
        label,
        validators=[
            Optional(),
            NumberRange(min=0, max=2, message="Priority must be between 0 and 2"),
        ],
        default=0,
    )


def normalize_priority(item):
    """
    Apply the supported priority range server-side as a last safety net.
    """
    if getattr(item, "priority", None) is None:
        item.priority = 0
    item.priority = int(item.priority)
    if item.priority < 0 or item.priority > 2:
        raise ValueError("Priority must be between 0 and 2")
    return item.priority


class RemoteSelect2ManyWidget:
    """
    Render a multiple select fed by remote Select2 calls.
    """

    def __init__(self, endpoint, placeholder="Select Value"):
        self.endpoint = endpoint
        self.placeholder = placeholder

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        kwargs.setdefault("name", field.name)
        kwargs["class"] = "plum-select2-remote form-control"
        kwargs["multiple"] = "multiple"
        kwargs["data-placeholder"] = self.placeholder
        endpoint = self.endpoint
        if not endpoint.startswith("/"):
            endpoint = url_for(endpoint)
        kwargs["data-remote-url"] = endpoint

        options = []
        for value, label in field.selected_options():
            options.append(
                f'<option value="{escape(value)}" selected="selected">{escape(label)}</option>'
            )

        return Markup(
            f"<select {html_params(**kwargs)}>{''.join(options)}</select>"
        )


class RemoteSelect2Widget:
    """
    Render a single select fed by remote Select2 calls.
    """

    def __init__(self, endpoint, placeholder="Select Value"):
        self.endpoint = endpoint
        self.placeholder = placeholder

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        kwargs.setdefault("name", field.name)
        kwargs["class"] = "plum-select2-remote form-control"
        kwargs["data-placeholder"] = self.placeholder
        endpoint = self.endpoint
        if not endpoint.startswith("/"):
            endpoint = url_for(endpoint)
        kwargs["data-remote-url"] = endpoint

        options = ['<option value=""></option>']
        for value, label in field.selected_options():
            options.append(
                f'<option value="{escape(value)}" selected="selected">{escape(label)}</option>'
            )

        return Markup(
            f"<select {html_params(**kwargs)}>{''.join(options)}</select>"
        )


class RemoteRelatedMultipleField(Field):
    """
    Lightweight remote-loaded relation field for many-to-many selections.
    """

    def __init__(
        self,
        label=None,
        validators=None,
        datamodel=None,
        col_name=None,
        endpoint=None,
        **kwargs,
    ):
        super().__init__(label, validators, **kwargs)
        self.datamodel = datamodel
        self.col_name = col_name
        self._invalid_formdata = []
        self.widget = RemoteSelect2ManyWidget(endpoint)

    def _get_related_interface(self):
        return self.datamodel.get_related_interface(self.col_name)

    def process_data(self, value):
        self.data = list(value) if value else []

    def process_formdata(self, valuelist):
        rel_datamodel = self._get_related_interface()
        self._invalid_formdata = []
        if not valuelist:
            self.data = []
            return

        items = []
        for raw_value in valuelist:
            obj = rel_datamodel.get(raw_value)
            if obj is None:
                self._invalid_formdata.append(raw_value)
            else:
                items.append(obj)
        self.data = items

    def pre_validate(self, form):
        if self._invalid_formdata:
            raise ValidationError("Not a valid choice")

    def selected_options(self):
        rel_datamodel = self._get_related_interface()
        for obj in self.data or []:
            yield str(rel_datamodel.get_pk_value(obj)), str(obj)


class RemoteRelatedField(Field):
    """
    Lightweight remote-loaded relation field for single-value selections.
    """

    def __init__(
        self,
        label=None,
        validators=None,
        datamodel=None,
        col_name=None,
        endpoint=None,
        **kwargs,
    ):
        super().__init__(label, validators, **kwargs)
        self.datamodel = datamodel
        self.col_name = col_name
        self._invalid_formdata = []
        self.widget = RemoteSelect2Widget(endpoint)

    def _get_related_interface(self):
        return self.datamodel.get_related_interface(self.col_name)

    def process_data(self, value):
        if not value:
            self.data = None
            return

        if hasattr(value, "__table__"):
            self.data = value
            return

        rel_datamodel = self._get_related_interface()
        lookup_value = int(value) if str(value).isdigit() else value
        self.data = rel_datamodel.get(lookup_value)

    def process_formdata(self, valuelist):
        rel_datamodel = self._get_related_interface()
        self._invalid_formdata = []

        raw_value = None
        for candidate in valuelist or []:
            candidate = str(candidate).strip()
            if candidate:
                raw_value = candidate
                break

        if raw_value is None:
            self.data = None
            return

        lookup_value = int(raw_value) if raw_value.isdigit() else raw_value
        obj = rel_datamodel.get(lookup_value)
        if obj is None:
            self._invalid_formdata.append(raw_value)
            self.data = None
            return

        self.data = obj

    def pre_validate(self, form):
        if self._invalid_formdata:
            raise ValidationError("Not a valid choice")

    def selected_options(self):
        rel_datamodel = self._get_related_interface()
        if self.data is None:
            return
        yield str(rel_datamodel.get_pk_value(self.data)), str(self.data)


def get_job_uid(pk):
    """
    For Jinja and ajax queries, get a UID from ID
    """
    result = db.session.query(Jobs.uid).filter(Jobs.id == pk).scalar()
    return result


def get_target_value(pk):
    """
    For Jinja and ajax queries, get a netword/ip search query from target ID
    """
    result = db.session.query(Targets.value).filter(Targets.id == pk).scalar()
    if "/" in result:
        result = f"net:{result}"
    else:
        result = f"ip:{result}"
    return result


def _format_datetime_for_ui(value):
    """
    Render datetimes consistently on helper-backed templates.
    """
    value = ensure_utc_naive(value)
    if value is None:
        return None
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _format_scan_duration(last_scan, previous_scan):
    """
    Compute a human-readable duration from two timestamps.
    """
    last_scan = ensure_utc_naive(last_scan)
    previous_scan = ensure_utc_naive(previous_scan)
    if not last_scan or not previous_scan:
        return "∞"

    diff = last_scan - previous_scan
    total_seconds = int(diff.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    if minutes:
        return f"{minutes:02d}:{seconds:02d}"
    return f"{seconds}s"


def get_target_profile_stats(pk):
    """
    Return the effective profile runtime stats for one target.
    """
    target = db.session.query(Targets).filter(Targets.id == pk).one_or_none()
    if target is None:
        return []

    profiles = {profile.id: profile for profile in target.scanprofiles}
    apply_all_profiles = (
        db.session.query(ScanProfiles)
        .filter(ScanProfiles.apply_to_all == True)
        .order_by(ScanProfiles.name.asc())
        .all()
    )
    for profile in apply_all_profiles:
        profiles.setdefault(profile.id, profile)

    states = {
        state.scanprofile_id: state
        for state in db.session.query(TargetScanStates)
        .filter(TargetScanStates.target_id == pk)
        .all()
    }

    rows = []
    for profile in sorted(profiles.values(), key=lambda item: (item.name or "").lower()):
        state = states.get(profile.id)
        last_scan = ensure_utc_naive(state.last_scan) if state else None
        previous_scan = ensure_utc_naive(state.last_previous_scan) if state else None
        rows.append(
            {
                "profile_id": profile.id,
                "profile_name": profile.name,
                "scan_cycle_minutes": profile.scan_cycle_minutes,
                "apply_to_all": profile.apply_to_all,
                "working": bool(state.working) if state else False,
                "last_scan": _format_datetime_for_ui(last_scan),
                "last_previous_scan": _format_datetime_for_ui(previous_scan),
                "duration": _format_scan_duration(last_scan, previous_scan),
            }
        )

    return rows


# Add a Functions to jinja
app.jinja_env.globals["get_job_uid"] = get_job_uid
app.jinja_env.globals["get_target_value"] = get_target_value
app.jinja_env.globals["get_target_profile_stats"] = get_target_profile_stats


@appbuilder.app.errorhandler(404)
def page_not_found(e):
    """
    Application wide 404 error handler
    """
    _ = e
    return (
        render_template(
            "404.html", base_template=appbuilder.base_template, appbuilder=appbuilder
        ),
        404,
    )


# Connect to the Mieili DB
client = Client(
    db.app.config.get("MEILI_DATABASE_URI"),
    db.app.config.get("MEILI_KEY"),
)


class MeiliSearchView(BaseView):
    """
    This class interact with the meili database and allow basic search
    """

    default_view = "search"

    @expose("/query")
    def query(self):
        """
        This Function send the query back to meilisearch.
        """
        query = request.args.get("q", "")
        index = client.index("plum")
        results = index.search(query)
        return jsonify(results)

    @expose("/search")
    def search(self):
        """
        This function display the search page
        """
        return self.render_template("search_meili.html")

    @expose("/getuid")
    def getuid(self):
        """
        This function retrieve a document from the meili.

        """
        uid = request.args.get("uid", "")
        index = client.index("plum")
        try:
            result = index.get_document(uid)
            return jsonify(vars(result))  # doc is already a dict-like
        except Exception as e:
            return jsonify({"error": str(e)}), 404


class KVSearchView(BaseView):
    """
    This class interact with the KvRocks database and allow basic search
    It return found document sorted by IP's.
    """

    default_view = "search"
    DEFAULT_SEARCH_MONTHS = 3
    SEARCH_PAGE_LIMIT = 100
    SEARCH_WINDOW_SECONDS = 24 * 60 * 60
    MAX_EXPORT_WARNINGS = 20

    @staticmethod
    def _subtract_months(date_value, months):
        """
        Subtract whole calendar months while keeping the date valid.
        """
        month = date_value.month - months
        year = date_value.year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        day = min(date_value.day, calendar.monthrange(year, month)[1])
        return date_value.replace(year=year, month=month, day=day)

    @staticmethod
    def _timestamp_to_iso(timestamp):
        """
        Format epoch seconds as UTC ISO for API responses.
        """
        return (
            datetime.fromtimestamp(timestamp, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @classmethod
    def _default_time_range(cls):
        """
        Return the default search range: now back to three calendar months.
        """
        to_date = datetime.now(timezone.utc)
        from_date = cls._subtract_months(to_date, cls.DEFAULT_SEARCH_MONTHS)
        return int(from_date.timestamp()), int(to_date.timestamp())

    @classmethod
    def _resolve_time_range(cls, from_value=None, to_value=None):
        """
        Parse and validate request-provided timestamps.
        """
        default_from, default_to = cls._default_time_range()
        from_ts = KVrocksIndexer.normalize_timestamp(from_value)
        to_ts = KVrocksIndexer.normalize_timestamp(to_value)

        if from_value in (None, ""):
            from_ts = default_from
        if to_value in (None, ""):
            to_ts = default_to

        if from_ts is None or to_ts is None:
            return None, False, "Invalid time range"
        if from_ts > to_ts:
            return None, False, "Start time must be before end time"

        return {
            "from_ts": from_ts,
            "to_ts": to_ts,
            "from_iso": cls._timestamp_to_iso(from_ts),
            "to_iso": cls._timestamp_to_iso(to_ts),
        }, True, None

    @staticmethod
    def _build_timestamp_array(indexer, results_ip):
        """
        Build per-IP timestamp metadata for a search result map.
        """
        timestamp_array = {}
        for ip in results_ip:
            ip_timestamps = indexer.get_timestamp_for_ip(ip)
            filtered_timestamps = {
                uid: ip_timestamps[uid]
                for uid in results_ip[ip]
                if uid in ip_timestamps
            }

            min_seen = None
            max_seen = None
            for uid_data in filtered_timestamps.values():
                first_seen = uid_data.get("first_seen")
                last_seen = uid_data.get("last_seen")
                if first_seen is not None:
                    min_seen = first_seen if min_seen is None else min(
                        min_seen, first_seen
                    )
                if last_seen is not None:
                    max_seen = last_seen if max_seen is None else max(
                        max_seen, last_seen
                    )

            filtered_timestamps["min_seen"] = min_seen
            filtered_timestamps["max_seen"] = max_seen
            timestamp_array[ip] = filtered_timestamps
        return timestamp_array

    def _get_matching_uids(self, indexer, criteria_groups, scoped_uids=None):
        """
        Resolve OR query groups into one UID set before time slicing.
        """
        matching_uids = set()
        for criteria in criteria_groups:
            criteria = lowercase_dict(criteria)
            logger.debug(criteria)
            if scoped_uids is None:
                matching_uids.update(indexer.get_uids_by_criteria(criteria))
            else:
                matching_uids.update(
                    indexer.get_uids_by_criteria_scoped(criteria, scoped_uids)
                )
        return matching_uids

    @staticmethod
    def _get_export_jobs_folder():
        export_jobs_folder = db.app.config["EXPORT_JOBS_FOLDER"]
        os.makedirs(export_jobs_folder, exist_ok=True)
        return export_jobs_folder

    @staticmethod
    def _serialize_job_state(job_state):
        elapsed_seconds = max(
            0.0,
            time.time() - job_state["created_ts"],
        )
        return {
            "job_id": job_state["job_id"],
            "status": job_state["status"],
            "export_type": job_state.get("export_type", "full_json"),
            "query": job_state["query"],
            "from_ts": job_state.get("from_ts"),
            "to_ts": job_state.get("to_ts"),
            "processed_uids": job_state["processed_uids"],
            "total_uids": job_state["total_uids"],
            "progress_percent": job_state["progress_percent"],
            "elapsed_seconds": elapsed_seconds,
            "download_ready": bool(job_state["file_path"])
            and job_state["status"] == "done",
            "error": job_state["error"],
            "warnings": job_state.get("warnings", []),
            "warning_count": job_state.get(
                "warning_count", len(job_state.get("warnings", []))
            ),
        }

    @staticmethod
    def _set_job_state(job_id, **updates):
        with EXPORT_JOB_STATES_LOCK:
            job_state = EXPORT_JOB_STATES.get(job_id)
            if not job_state:
                return None
            job_state.update(updates)
            total_uids = job_state.get("total_uids", 0) or 0
            processed_uids = job_state.get("processed_uids", 0) or 0
            if total_uids > 0:
                job_state["progress_percent"] = min(
                    100.0, (processed_uids / total_uids) * 100.0
                )
            elif job_state.get("status") == "done":
                job_state["progress_percent"] = 100.0
            else:
                job_state["progress_percent"] = 0.0
            return dict(job_state)

    @staticmethod
    def _add_job_warning(job_id, message):
        with EXPORT_JOB_STATES_LOCK:
            job_state = EXPORT_JOB_STATES.get(job_id)
            if not job_state:
                return None
            warnings = job_state.setdefault("warnings", [])
            job_state["warning_count"] = job_state.get("warning_count", 0) + 1
            if len(warnings) < KVSearchView.MAX_EXPORT_WARNINGS:
                warnings.append(message)
            return dict(job_state)

    @staticmethod
    def _get_job_state(job_id):
        with EXPORT_JOB_STATES_LOCK:
            job_state = EXPORT_JOB_STATES.get(job_id)
            return dict(job_state) if job_state else None

    @staticmethod
    def _get_owned_job(job_id):
        job_state = KVSearchView._get_job_state(job_id)
        if not job_state:
            return None
        if job_state["owner_user_id"] != getattr(current_user, "id", None):
            return False
        return job_state

    @staticmethod
    def _build_full_export_payload(query, results):
        index = client.index("plum")
        export_payload = {
            "query": query,
            "time_range": results.get("time_range"),
            "generated_at": utcnow_iso(),
            "results": {},
        }

        total_uids = sum(len(uids) for uids in results["results"].values())
        return export_payload, index, total_uids

    @staticmethod
    def _is_missing_meili_document(error):
        return "document_not_found" in str(error)

    @staticmethod
    def _load_meili_document(index, uid):
        """
        Load one Meilisearch document, tolerating missing documents.
        """
        try:
            result = index.get_document(uid)
            return vars(result), None, None
        except MeilisearchApiError as error:
            if not KVSearchView._is_missing_meili_document(error):
                raise
            warning = "document_not_found"
            warning_message = (
                f"Document {uid} is indexed in Kvrocks but missing "
                "from Meilisearch; exported metadata only."
            )
            return None, warning, warning_message

    @staticmethod
    def load_meili_document(index, uid):
        """
        Public wrapper for tolerant Meilisearch document loading.
        """
        return KVSearchView._load_meili_document(index, uid)

    @staticmethod
    def timestamp_to_iso(timestamp):
        """
        Public wrapper around UTC ISO timestamp formatting.
        """
        return KVSearchView._timestamp_to_iso(timestamp)

    @staticmethod
    def _run_full_export_job(job_id):
        with app.app_context():
            job_state = KVSearchView._get_job_state(job_id)
            if not job_state:
                return

            query = job_state["query"]
            results = KVSearchView().execute_search(
                query, job_state.get("from_ts"), job_state.get("to_ts")
            )
            if not results["status"]:
                KVSearchView._set_job_state(
                    job_id,
                    status="error",
                    error=results.get("msg_error") or "Invalid query",
                )
                return

            export_payload, index, total_uids = KVSearchView._build_full_export_payload(
                query, results
            )
            KVSearchView._set_job_state(
                job_id,
                status="running",
                total_uids=total_uids,
                processed_uids=0,
                error="",
            )

            processed_uids = 0
            try:
                for ip, uids in sorted(results["results"].items()):
                    ip_timestamps = results["timestamps"].get(ip, {})
                    export_payload["results"][ip] = []
                    for uid in uids:
                        document, warning, warning_message = (
                            KVSearchView._load_meili_document(index, uid)
                        )
                        if warning_message:
                            logger.warning(warning_message)
                            KVSearchView._add_job_warning(job_id, warning_message)

                        export_entry = {
                            "uid": uid,
                            "first_seen": ip_timestamps.get(uid, {}).get(
                                "first_seen"
                            ),
                            "last_seen": ip_timestamps.get(uid, {}).get(
                                "last_seen"
                            ),
                            "document": document,
                        }
                        if warning:
                            export_entry["warning"] = warning
                        export_payload["results"][ip].append(export_entry)
                        processed_uids += 1
                        KVSearchView._set_job_state(
                            job_id,
                            processed_uids=processed_uids,
                        )

                export_jobs_folder = KVSearchView._get_export_jobs_folder()
                file_path = os.path.join(export_jobs_folder, f"{job_id}.json")
                tmp_path = f"{file_path}.tmp"
                with open(tmp_path, "w", encoding="utf-8") as export_file:
                    json.dump(export_payload, export_file, indent=2)
                os.replace(tmp_path, file_path)

                KVSearchView._set_job_state(
                    job_id,
                    status="done",
                    processed_uids=processed_uids,
                    file_path=file_path,
                    finished_at=utcnow_iso(),
                )
            except Exception as error:
                logger.exception("Full export job %s failed", job_id)
                KVSearchView._set_job_state(
                    job_id,
                    status="error",
                    error=str(error),
                )

    @staticmethod
    def _run_ip_export_job(job_id):
        with app.app_context():
            job_state = KVSearchView._get_job_state(job_id)
            if not job_state:
                return

            query = job_state["query"]
            KVSearchView._set_job_state(job_id, status="running", error="")
            try:
                results = KVSearchView().execute_search(
                    query, job_state.get("from_ts"), job_state.get("to_ts")
                )
                if not results["status"]:
                    KVSearchView._set_job_state(
                        job_id,
                        status="error",
                        error=results.get("msg_error") or "Invalid query",
                    )
                    return

                ips = sorted(results["results"].keys())
                KVSearchView._set_job_state(
                    job_id,
                    total_uids=len(ips),
                    processed_uids=0,
                )

                export_jobs_folder = KVSearchView._get_export_jobs_folder()
                file_path = os.path.join(export_jobs_folder, f"{job_id}.txt")
                tmp_path = f"{file_path}.tmp"
                processed_ips = 0
                with open(tmp_path, "w", encoding="utf-8") as export_file:
                    for ip in ips:
                        export_file.write(f"{ip}\n")
                        processed_ips += 1
                        if processed_ips % 100 == 0 or processed_ips == len(ips):
                            KVSearchView._set_job_state(
                                job_id,
                                processed_uids=processed_ips,
                            )
                os.replace(tmp_path, file_path)

                KVSearchView._set_job_state(
                    job_id,
                    status="done",
                    processed_uids=processed_ips,
                    file_path=file_path,
                    finished_at=utcnow_iso(),
                )
            except Exception as error:
                logger.exception("IP export job %s failed", job_id)
                KVSearchView._set_job_state(
                    job_id,
                    status="error",
                    error=str(error),
                )

    def split_query_groups(self, query):
        """
        Split a query into AND groups separated by explicit OR tokens.
        """
        parts = shlex.split(query or "")
        if not parts:
            return [[]]

        groups = []
        current_group = []
        for part in parts:
            if part.upper() == "OR":
                groups.append(current_group)
                current_group = []
            else:
                current_group.append(part)
        groups.append(current_group)
        return groups

    def parse_query_group(self, query):
        """
        This function parse one AND-only query group.
        It validate if we got a good syntax and use only authorised keyywords.

        """

        valid_keywords = [
            "ip",
            "net",
            # "as",
            # "as_number",
            # "as_name",
            # "as_description",
            # "as_country",
            "fqdn",
            "fqdn_requested",
            "host",
            "domain",
            "tld",
            # "url_path",
            "port",
            # "protocol",
            "http_title",
            "http_favicon_path",
            "http_favicon_mmhash",
            "http_favicon_md5",
            "http_favicon_sha256",
            # "http_filename",
            "http_cookiename",
            "http_etag",
            "http_server",
            # "email",
            "x509_issuer",
            "x509_md5",
            "x509_sha1",
            "x509_sha256",
            "x509_subject",
            "x509_san",
            # "time_filter_before_after",
            # "ssh_fingerprint",
            # "ttl_count",
            # "hsh"
            "banner",
        ]

        valid_modifiers = {".lk", ".like", ".bg", ".begin", ".not", ".nt"}

        result = {}
        msg_error = None
        if isinstance(query, (list, tuple)):
            parts = list(query)
        else:
            try:
                parts = shlex.split(query or "")
            except ValueError as error:
                return {}, False, f"Invalid query syntax: {error}"
        for part in parts:
            if ":" not in part:
                msg_error = f"Bad keyword/value: {part}"
                continue

            key, value = part.split(":", 1)
            key = key.lower()
            # Determine base key without modifier
            base_key = key
            for suf in valid_modifiers:
                if key.endswith(suf):
                    base_key = key[: -len(suf)]
                    break

            if base_key not in valid_keywords:
                msg_error = f"Bad keyword: {key}"
                continue

            # store values in list to allow multiple occurrences
            if key not in result:
                result[key] = [value]
            else:
                result[key].append(value)

        status = True
        if msg_error:
            status = False
        return result, status, msg_error

    def parse_query(self, query):
        """
        Parse the full query, supporting explicit OR between AND groups.
        """
        try:
            query_groups = self.split_query_groups(query)
        except ValueError as error:
            return [], False, f"Invalid query syntax: {error}"
        parsed_groups = []
        error_messages = []

        for idx, group in enumerate(query_groups, start=1):
            if not group:
                error_messages.append(f"Empty query group around OR at segment {idx}")
                continue

            criteria, status, msg_error = self.parse_query_group(group)
            if not status:
                error_messages.append(msg_error or f"Invalid query group {idx}")
                continue
            parsed_groups.append(criteria)

        status = len(error_messages) == 0
        return parsed_groups, status, " | ".join(error_messages)

    def execute_search(self, query, from_ts=None, to_ts=None):
        """
        Shared search executor used by both JSON and export endpoints.
        """
        start_time = time.time()
        query = query or ""
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        count_objects = indexer.objects_count()  # Get object count in db
        time_range, time_status, time_error = self._resolve_time_range(from_ts, to_ts)
        if not time_status:
            end_time = time.time()
            return {
                "status": False,
                "results": {},
                "timestamps": {},
                "msg_error": time_error or "Invalid time range",
                "processingTimeMs": (end_time - start_time) * 1000,
                "uid_count": count_objects.get("uid_count"),
                "ip_count": count_objects.get("ip_count"),
                "time_range": {},
            }

        criteria_groups, status, msg_error = self.parse_query(query)
        results_ip = {}
        timestamp_array = {}

        if status:
            time_uids = indexer.get_uids_by_time_range(
                time_range["from_ts"], time_range["to_ts"]
            )
            uids = list(self._get_matching_uids(indexer, criteria_groups).intersection(time_uids))
            results_ip = indexer.get_ip_from_uids(uids)
            timestamp_array = self._build_timestamp_array(indexer, results_ip)

            sorted_ips = sorted(
                results_ip,
                key=lambda ip: (
                    -(timestamp_array.get(ip, {}).get("max_seen") or -1),
                    ip,
                ),
            )
            results_ip = {ip: results_ip[ip] for ip in sorted_ips}
            timestamp_array = {ip: timestamp_array[ip] for ip in sorted_ips}

        end_time = time.time()
        processingtimems = (end_time - start_time) * 1000
        returned_results = len(results_ip) if status else 0

        return {
            "status": status,
            "results": results_ip if status else {},
            "timestamps": timestamp_array if status else {},
            "msg_error": msg_error or "",
            "processingTimeMs": processingtimems,
            "uid_count": count_objects.get("uid_count"),
            "ip_count": count_objects.get("ip_count"),
            "time_range": time_range,
            "pagination": {
                "offset": 0,
                "limit": None,
                "returned": returned_results,
                "total": returned_results,
                "has_more": False,
                "next_offset": returned_results,
            },
        }

    def execute_search_page(
        self,
        query,
        from_ts=None,
        to_ts=None,
        cursor_ts=None,
        seen_ips=None,
        limit=None,
        window_days=None,
    ):
        """
        Fast UI search: inspect one last_seen window backwards from cursor_ts.
        """
        start_time = time.time()
        query = query or ""
        limit = limit or self.SEARCH_PAGE_LIMIT
        probe_limit = limit + 1
        seen_ips = set(seen_ips or [])
        try:
            window_days = max(1, min(int(window_days or 1), 4096))
        except (TypeError, ValueError):
            window_days = 1
        window_seconds = window_days * self.SEARCH_WINDOW_SECONDS
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        count_objects = indexer.objects_count()
        time_range, time_status, time_error = self._resolve_time_range(from_ts, to_ts)
        if not time_status:
            return {
                "status": False,
                "results": {},
                "timestamps": {},
                "msg_error": time_error or "Invalid time range",
                "processingTimeMs": (time.time() - start_time) * 1000,
                "uid_count": count_objects.get("uid_count"),
                "ip_count": count_objects.get("ip_count"),
                "time_range": {},
                "pagination": {},
            }

        criteria_groups, status, msg_error = self.parse_query(query)
        results_ip = {}
        timestamp_array = {}
        scanned_days = 0
        exhausted = True

        cursor_ts = KVrocksIndexer.normalize_timestamp(cursor_ts)
        if cursor_ts is None or cursor_ts > time_range["to_ts"]:
            cursor_ts = time_range["to_ts"]
        if cursor_ts < time_range["from_ts"]:
            cursor_ts = time_range["from_ts"] - 1

        next_cursor = cursor_ts
        stopped_in_window = False
        if status and cursor_ts >= time_range["from_ts"]:
            current_to = cursor_ts
            current_from = max(
                current_to - window_seconds + 1,
                time_range["from_ts"],
            )
            scanned_days = max(
                1,
                int((current_to - current_from) / self.SEARCH_WINDOW_SECONDS) + 1,
            )
            window_uids = indexer.get_uids_by_last_seen_range(
                current_from, current_to
            )
            page_uids = self._get_matching_uids(
                indexer, criteria_groups, scoped_uids=window_uids
            )
            day_ip_map = indexer.get_ip_from_uids(page_uids)
            day_timestamps = self._build_timestamp_array(indexer, day_ip_map)
            sorted_ips = sorted(
                day_ip_map,
                key=lambda ip: (
                    -(day_timestamps.get(ip, {}).get("max_seen") or -1),
                    ip,
                ),
            )

            for ip in sorted_ips:
                if ip in seen_ips or ip in results_ip:
                    continue
                results_ip[ip] = day_ip_map[ip]
                timestamp_array[ip] = day_timestamps[ip]
                if len(results_ip) >= probe_limit:
                    stopped_in_window = True
                    break

            if stopped_in_window:
                next_cursor = current_to
                exhausted = False
            else:
                next_cursor = current_from - 1
                exhausted = next_cursor < time_range["from_ts"]

        processingtimems = (time.time() - start_time) * 1000
        has_more = bool(status and not exhausted)
        if status and len(results_ip) > limit:
            displayed_ips = list(results_ip)[:limit]
            results_ip = {ip: results_ip[ip] for ip in displayed_ips}
            timestamp_array = {
                ip: timestamp_array[ip]
                for ip in displayed_ips
                if ip in timestamp_array
            }
        returned_results = len(results_ip) if status else 0
        shown_count = len(seen_ips) + returned_results

        return {
            "status": status,
            "results": results_ip if status else {},
            "timestamps": timestamp_array if status else {},
            "msg_error": msg_error or "",
            "processingTimeMs": processingtimems,
            "uid_count": count_objects.get("uid_count"),
            "ip_count": count_objects.get("ip_count"),
            "time_range": time_range,
            "pagination": {
                "limit": limit,
                "returned": returned_results,
                "shown": shown_count,
                "has_more": has_more,
                "next_cursor": next_cursor,
                "scanned_days": scanned_days,
                "window_days": window_days,
                "stopped_in_window": stopped_in_window,
            },
        }

    @expose("/query")
    @has_access
    def query(self):
        """
        This Function send the query back to KVRocks
        """
        query = request.args.get("q", "")
        seen_ips = [
            ip.strip()
            for ip in request.args.get("seen_ips", "").split(",")
            if ip.strip()
        ]
        try:
            limit = min(max(int(request.args.get("limit", 100)), 1), 500)
        except (TypeError, ValueError):
            return jsonify({"status": False, "msg_error": "Invalid pagination"}), 400
        results = self.execute_search_page(
            query,
            request.args.get("from_ts"),
            request.args.get("to_ts"),
            cursor_ts=request.args.get("cursor_ts"),
            seen_ips=seen_ips,
            limit=limit,
            window_days=request.args.get("window_days"),
        )
        return jsonify(results)

    @expose("/export")
    @has_access
    def export(self):
        """
        Export plain-text list of IPs for a search query.
        """
        query = request.args.get("q", "")
        if not query:
            return make_response("Missing 'q' parameter", 400)

        results = self.execute_search(
            query, request.args.get("from_ts"), request.args.get("to_ts")
        )
        if not results["status"]:
            msg = results.get("msg_error") or "Invalid query"
            return make_response(msg, 400)

        ips = sorted(results["results"].keys())
        payload = "\n".join(ips)
        if ips:
            payload += "\n"
        response = make_response(payload)
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Content-Disposition"] = "attachment; filename=ip_list.txt"
        return response

    @expose("/export_full_start", methods=["POST"])
    @has_access
    def export_full_start(self):
        """
        Start an asynchronous export of the current filtered data set.
        """
        payload = request.get_json(silent=True) or {}
        query = payload.get("q", "").strip()
        if not query:
            return jsonify({"error": "Missing query"}), 400

        time_range, time_status, time_error = self._resolve_time_range(
            payload.get("from_ts"), payload.get("to_ts")
        )
        if not time_status:
            return jsonify({"error": time_error or "Invalid time range"}), 400

        job_id = str(uuid.uuid4())
        owner_user_id = getattr(current_user, "id", None)
        owner_username = getattr(current_user, "username", "")
        with EXPORT_JOB_STATES_LOCK:
            EXPORT_JOB_STATES[job_id] = {
                "job_id": job_id,
                "export_type": "full_json",
                "owner_user_id": owner_user_id,
                "owner_username": owner_username,
                "status": "queued",
                "query": query,
                "from_ts": time_range["from_ts"],
                "to_ts": time_range["to_ts"],
                "created_ts": time.time(),
                "processed_uids": 0,
                "total_uids": 0,
                "progress_percent": 0.0,
                "file_path": None,
                "error": "",
                "warnings": [],
                "warning_count": 0,
                "finished_at": None,
            }

        worker = threading.Thread(
            target=self._run_full_export_job,
            args=(job_id,),
            daemon=True,
        )
        worker.start()
        return jsonify({"job_id": job_id})

    @expose("/export_ips_start", methods=["POST"])
    @has_access
    def export_ips_start(self):
        """
        Start an asynchronous export of the current filtered IP list.
        """
        payload = request.get_json(silent=True) or {}
        query = payload.get("q", "").strip()
        if not query:
            return jsonify({"error": "Missing query"}), 400

        time_range, time_status, time_error = self._resolve_time_range(
            payload.get("from_ts"), payload.get("to_ts")
        )
        if not time_status:
            return jsonify({"error": time_error or "Invalid time range"}), 400

        job_id = str(uuid.uuid4())
        owner_user_id = getattr(current_user, "id", None)
        owner_username = getattr(current_user, "username", "")
        with EXPORT_JOB_STATES_LOCK:
            EXPORT_JOB_STATES[job_id] = {
                "job_id": job_id,
                "export_type": "ip_list",
                "owner_user_id": owner_user_id,
                "owner_username": owner_username,
                "status": "queued",
                "query": query,
                "from_ts": time_range["from_ts"],
                "to_ts": time_range["to_ts"],
                "created_ts": time.time(),
                "processed_uids": 0,
                "total_uids": 0,
                "progress_percent": 0.0,
                "file_path": None,
                "error": "",
                "warnings": [],
                "warning_count": 0,
                "finished_at": None,
            }

        worker = threading.Thread(
            target=self._run_ip_export_job,
            args=(job_id,),
            daemon=True,
        )
        worker.start()
        return jsonify({"job_id": job_id})

    @expose("/export_full_status")
    @has_access
    def export_full_status(self):
        """
        Return asynchronous export job state for the current user.
        """
        job_id = request.args.get("job_id", "")
        job_state = self._get_owned_job(job_id)
        if job_state is None:
            return jsonify({"error": "Unknown export job"}), 404
        if job_state is False:
            return jsonify({"error": "Forbidden"}), 403
        return jsonify(self._serialize_job_state(job_state))

    @expose("/export_ips_status")
    @has_access
    def export_ips_status(self):
        """
        Return asynchronous IP export job state for the current user.
        """
        job_id = request.args.get("job_id", "")
        job_state = self._get_owned_job(job_id)
        if job_state is None:
            return jsonify({"error": "Unknown export job"}), 404
        if job_state is False:
            return jsonify({"error": "Forbidden"}), 403
        return jsonify(self._serialize_job_state(job_state))

    @expose("/export_full_download")
    @has_access
    def export_full_download(self):
        """
        Download the completed asynchronous export file.
        """
        job_id = request.args.get("job_id", "")
        job_state = self._get_owned_job(job_id)
        if job_state is None:
            return make_response("Unknown export job", 404)
        if job_state is False:
            return make_response("Forbidden", 403)
        if job_state.get("export_type") != "full_json":
            return make_response("Wrong export type", 409)
        if job_state["status"] != "done" or not job_state.get("file_path"):
            return make_response("Export not ready", 409)
        if not os.path.exists(job_state["file_path"]):
            return make_response("Export file missing", 410)

        return send_file(
            job_state["file_path"],
            as_attachment=True,
            download_name=f"plum_export_{job_id}.json",
            mimetype="application/json",
        )

    @expose("/export_ips_download")
    @has_access
    def export_ips_download(self):
        """
        Download the completed asynchronous IP export file.
        """
        job_id = request.args.get("job_id", "")
        job_state = self._get_owned_job(job_id)
        if job_state is None:
            return make_response("Unknown export job", 404)
        if job_state is False:
            return make_response("Forbidden", 403)
        if job_state.get("export_type") != "ip_list":
            return make_response("Wrong export type", 409)
        if job_state["status"] != "done" or not job_state.get("file_path"):
            return make_response("Export not ready", 409)
        if not os.path.exists(job_state["file_path"]):
            return make_response("Export file missing", 410)

        return send_file(
            job_state["file_path"],
            as_attachment=True,
            download_name="ip_list.txt",
            mimetype="text/plain",
        )

    @expose("/search")
    def search(self):
        """
        This fuction display the search page
        """
        return self.render_template("search_kvrocks.html")


class IPDetailView(BaseView):
    """
    Display the cumulative details for one IP without time filtering.
    """

    route_base = "/ip"
    default_view = "detail"

    @staticmethod
    def _safe_timestamp_to_iso(timestamp):
        """
        Convert epoch-like values to UTC ISO when possible.
        """
        if timestamp in (None, ""):
            return None
        try:
            return KVSearchView.timestamp_to_iso(int(timestamp))
        except (TypeError, ValueError, OverflowError, OSError):
            return None

    @staticmethod
    def _safe_timestamp_to_display(timestamp):
        """
        Convert epoch-like values to DD/MM/YY when possible.
        """
        if timestamp in (None, ""):
            return None
        try:
            return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime(
                "%d/%m/%y"
            )
        except (TypeError, ValueError, OverflowError, OSError):
            return None

    @staticmethod
    def _port_group_sort_key(group):
        """
        Sort ports by protocol then numeric port when available.
        """
        portid = str(group.get("portid") or "")
        if portid.isdigit():
            return (group.get("protocol") or "", 0, int(portid), portid)
        return (group.get("protocol") or "", 1, portid)

    @staticmethod
    def _extract_hostname_details(hostnames):
        """
        Split Nmap hostname entries into PTR and generic resolved names.
        """
        ptr_records = []
        resolved_hosts = []
        seen_ptr = set()
        seen_hosts = set()

        for entry in hostnames or []:
            if isinstance(entry, dict):
                name = (entry.get("name") or entry.get("hostname") or "").strip()
                record_type = str(entry.get("type") or "").upper()
            else:
                name = str(entry).strip()
                record_type = ""

            if not name:
                continue

            if record_type == "PTR":
                if name not in seen_ptr:
                    ptr_records.append(name)
                    seen_ptr.add(name)
                continue

            if name not in seen_hosts:
                resolved_hosts.append(name)
                seen_hosts.add(name)

        return ptr_records, resolved_hosts

    @staticmethod
    def _strip_geolookup_meta(payload):
        """
        Remove CIRCL geolookup metadata from the response payload.
        """
        entries = payload if isinstance(payload, list) else [payload]
        cleaned = []
        for entry in entries:
            if isinstance(entry, dict):
                cleaned.append({key: value for key, value in entry.items() if key != "meta"})
            else:
                cleaned.append(entry)
        return cleaned

    @staticmethod
    def _parse_pdns_ndjson(payload):
        """
        Parse CIRCL Passive DNS NDJSON payload into a list of records.
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

    @expose("/pdns/<string:ip>")
    @has_access
    def passive_dns(self, ip):
        """
        Same-origin proxy for CIRCL Passive DNS.
        """
        if not is_valid_ip(ip):
            return jsonify({"error": "Invalid IP"}), 400

        passive_user = db.app.config.get("PASSIVE_USER", "")
        passive_pwd = db.app.config.get("PASSIVE_PWD", "")
        if not passive_user:
            return jsonify(
                {
                    "disabled": True,
                    "message": "CIRCL Passive DNS Disabled in configuration",
                }
            )
        if not passive_pwd:
            return jsonify({"error": "Passive DNS password is not configured"}), 503

        try:
            response = requests.get(
                f"https://www.circl.lu/pdns/query/{ip}",
                auth=(passive_user, passive_pwd),
                headers={"dribble-disable-active-query": "1"},
                timeout=15,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            logger.warning("CIRCL passive DNS failed for %s: %s", ip, error)
            return jsonify({"error": "Passive DNS lookup failed"}), 502

        records = self._parse_pdns_ndjson(response.text)
        return jsonify(records)

    @expose("/geolookup/<string:ip>")
    @has_access
    def geolookup(self, ip):
        """
        Same-origin proxy for CIRCL geolookup to avoid browser CORS issues.
        """
        if not is_valid_ip(ip):
            return jsonify({"error": "Invalid IP"}), 400

        try:
            response = requests.get(
                f"https://ip.circl.lu/geolookup/{ip}",
                timeout=10,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as error:
            logger.warning("CIRCL geolookup failed for %s: %s", ip, error)
            return jsonify({"error": "Lookup failed"}), 502
        except ValueError as error:
            logger.warning("CIRCL geolookup returned invalid JSON for %s: %s", ip, error)
            return jsonify({"error": "Invalid lookup response"}), 502

        return jsonify(self._strip_geolookup_meta(payload))

    @expose("/<string:ip>")
    @has_access
    def detail(self, ip):
        """
        Render a fully expanded detail page for one IP.
        """
        if not is_valid_ip(ip):
            return make_response("Invalid IP", 400)

        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        ip_timestamps = indexer.get_timestamp_for_ip(ip)
        uids = [uid for uid in ip_timestamps if uid not in ("min_seen", "max_seen")]
        sorted_uids = sorted(
            uids,
            key=lambda uid: (
                -(ip_timestamps.get(uid, {}).get("last_seen") or -1),
                uid,
            ),
        )

        index = client.index("plum")
        port_groups = {}
        unmapped_documents = []
        warnings = []
        requested_hostnames = set()
        for uid in sorted_uids:
            uid_timestamps = ip_timestamps.get(uid, {})
            first_seen = self._safe_timestamp_to_display(
                uid_timestamps.get("first_seen")
            )
            last_seen = self._safe_timestamp_to_display(
                uid_timestamps.get("last_seen")
            )
            document, _warning, warning_message = KVSearchView.load_meili_document(
                index, uid
            )
            if warning_message:
                warnings.append(warning_message)
                logger.warning(warning_message)
                unmapped_documents.append(
                    {
                        "uid": uid,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "warning": warning_message,
                    }
                )
                continue

            body = document.get("body") or {}
            user_hostnames = []
            for hostname_entry in body.get("hostnames") or []:
                if not isinstance(hostname_entry, dict):
                    continue
                if str(hostname_entry.get("type") or "").lower() != "user":
                    continue
                hostname = str(hostname_entry.get("name") or "").strip()
                if hostname:
                    requested_hostnames.add(hostname)
                    user_hostnames.append(hostname)
            ports = body.get("ports") or []
            if not ports:
                unmapped_documents.append(
                    {
                        "uid": uid,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "warning": "Document has no port details.",
                    }
                )
                continue

            scan_start = self._safe_timestamp_to_display(body.get("starttime"))
            scan_end = self._safe_timestamp_to_display(body.get("endtime"))
            ptr_records, resolved_hosts = self._extract_hostname_details(
                body.get("hostnames") or []
            )
            for port in ports:
                protocol = str(port.get("protocol") or "unknown").lower()
                portid = str(port.get("portid") or "?")
                group_key = f"{protocol}:{portid}"
                service_name = ((port.get("service") or {}).get("name")) or None
                group = port_groups.setdefault(
                    group_key,
                    {
                        "protocol": protocol,
                        "portid": portid,
                        "service_names": set(),
                        "observations": [],
                    },
                )
                if service_name:
                    group["service_names"].add(service_name)
                group["observations"].append(
                    {
                        "uid": uid,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "tab_label": last_seen or first_seen or uid,
                        "timestamp_sort": uid_timestamps.get("last_seen")
                        or uid_timestamps.get("first_seen")
                        or 0,
                        "scan_start": scan_start,
                        "scan_end": scan_end,
                        "ptr_records": ptr_records,
                        "resolved_hosts": resolved_hosts,
                        "user_hostnames": sorted(set(user_hostnames), key=str.lower),
                        "port": port,
                    }
                )

        port_cards = []
        for group in port_groups.values():
            group["service_names"] = sorted(group["service_names"])
            group["observations"].sort(
                key=lambda item: ((item.get("timestamp_sort") or 0), item["uid"])
            )
            group["observation_count"] = len(group["observations"])
            port_cards.append(group)
        port_cards.sort(key=self._port_group_sort_key)

        return self.render_template(
            "ip_detail.html",
            ip=ip,
            total_documents=len(sorted_uids),
            total_ports=len(port_cards),
            first_seen=(
                self._safe_timestamp_to_display(ip_timestamps.get("min_seen"))
            ),
            last_seen=(
                self._safe_timestamp_to_display(ip_timestamps.get("max_seen"))
            ),
            port_cards=port_cards,
            unmapped_documents=unmapped_documents,
            requested_hostnames=sorted(requested_hostnames, key=str.lower),
            warnings=warnings,
        )


class BulkImportForm(FlaskForm):
    """
    Flask Form for Bulk import
    """

    bulk = TextAreaField("Message Body")
    submit = SubmitField(label="Import")


class TargetsView(ModelView):
    """
    This class implements the GUI for targets
    """

    datamodel = SQLAInterface(Targets)
    add_template = "add_targetsview.html"
    edit_template = "edit_targetsview.html"
    list_template = "list_targetsview.html"
    list_columns = ["value", "description", "last_scan", "active", "working"]
    search_columns = ["value", "description", "active", "working", "scanprofiles"]
    label_columns = {
        "value": "CIDR/Host",
        "scanprofiles": "Scan profiles",
        "duration_html": "Scan Cycle",
    }
    search_form_extra_fields = {
        "scanprofiles": RemoteRelatedMultipleField(
            "Scan profiles",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="scanprofiles",
            endpoint="TargetsView.scanprofiles_remote",
        )
    }
    add_form_extra_fields = {
        "scanprofiles": RemoteRelatedMultipleField(
            "Scan profiles",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="scanprofiles",
            endpoint="TargetsView.scanprofiles_remote",
        )
    }
    edit_form_extra_fields = {
        "scanprofiles": RemoteRelatedMultipleField(
            "Scan profiles",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="scanprofiles",
            endpoint="TargetsView.scanprofiles_remote",
        )
    }
    add_columns = ["value", "description", "active", "scanprofiles"]
    edit_columns = ["value", "description", "active", "working", "scanprofiles"]
    show_columns = [
        "value",
        "description",
        "active",
        "working",
        "scanprofiles",
        "last_scan",
        "duration_html",
    ]
    search_exclude_columns = ["jobs"]
    base_order = ("last_scan", "desc")  # Latest finished on top.
    show_template = "show_targetsview.html"  # Custom Show view with results

    @staticmethod
    def _remote_limit():
        try:
            return min(int(request.args.get("limit", 30)), 100)
        except (TypeError, ValueError):
            return 30

    @staticmethod
    def _remote_ids():
        raw_ids = []
        if request.args.get("ids"):
            raw_ids.extend(request.args.get("ids", "").split(","))
        raw_ids.extend(request.args.getlist("ids"))

        ids = []
        for raw_id in raw_ids:
            raw_id = str(raw_id).strip()
            if raw_id.isdigit():
                ids.append(int(raw_id))
        return list(dict.fromkeys(ids))

    @staticmethod
    def _json_results(items):
        return jsonify([{"id": item.id, "text": str(item)} for item in items])

    @expose("/scanprofiles_remote", methods=["GET"])
    @has_access
    def scanprofiles_remote(self):
        """
        AJAX endpoint for scan profile lookup on target forms and filters.
        """
        query = request.args.get("q", "").strip()
        limit = self._remote_limit()
        selected_ids = self._remote_ids()

        if selected_ids:
            items = (
                db.session.query(ScanProfiles)
                .filter(ScanProfiles.id.in_(selected_ids))
                .order_by(ScanProfiles.name.asc())
                .all()
            )
            return self._json_results(items)

        if len(query) < 1:
            return jsonify([])

        items = (
            db.session.query(ScanProfiles)
            .filter(ScanProfiles.name.ilike(f"%{query}%"))
            .order_by(ScanProfiles.name.asc())
            .limit(limit)
            .all()
        )
        return self._json_results(items)

    @action(
        "mulresolvehwois",
        "Refresh Network informations",
        "Refresh Network informations ?",
        "fa-rocket",
        single=False,
    )
    def mulrreslovewhois(self, items):
        """
        Implement Raise priority of job to 2
        """
        if isinstance(items, list):
            # Raise N record
            for item in items:
                info = get_asn_description_for_ip(item.value)
                item.description = info
        else:
            # Raise Un tag
            info = get_asn_description_for_ip(item.value)
            item.description = info
        db.session.commit()
        self.update_redirect()
        return redirect(self.get_redirect())

    @action(
        "muldelete", "Delete Job", "Delete all Really?", "fa-trash-can", single=False
    )
    def muldelete(self, items):
        """
        Implement Multiple Delete for Targets
        """
        self.datamodel.delete_all(items)
        self.update_redirect()
        return redirect(self.get_redirect())

    @staticmethod
    def do_bulk_import(ips):
        """
        Import a list of bulk Ip's into the targets
        """
        log = ""
        ips = ips.split("\r")
        for ip in ips:
            ip_clean = ip.strip("\n ,;'\"")  # remove surrounding "Spc ,; and all quotes
            if ip_clean == "":
                pass
            if is_valid_fqdn(ip_clean):
                # If we got an FQDN too.
                new_target = Targets()
                new_target.description = "Bulk Import"
                new_target.value = ip_clean
                db.session.add(new_target)
                try:
                    db.session.commit()
                    log += f"{ip_clean} FQDN Processed\n"
                except IntegrityError:
                    # We Update bot info, IP / Last Seen at each beacon.
                    db.session.rollback()
                    log += f"{ip_clean} Not Processed, Target already in the database\n"
            elif is_valid_ip(ip_clean) or is_valid_cidr(ip_clean):
                new_target = Targets()
                new_target.description = "Bulk Import"
                new_target.value = is_valid_ip_or_cidr(
                    ip_clean
                )  # Set the First Ip in CIDR
                db.session.add(new_target)
                try:
                    db.session.commit()
                    log += f"{ip_clean} Processed\n"
                except IntegrityError:
                    # We Update bot info, IP / Last Seen at each beacon.
                    db.session.rollback()
                    log += f"{ip_clean} Not Processed, Target already in the database\n"
            else:
                log += f"{ip_clean} Invalid IP/CIDR/FQDN or private IP\n"
        return log

    @expose("/bulk_import", methods=["GET", "POST"])
    def bulk_import(self):
        """Bulk Import Form"""
        form = BulkImportForm()
        form.bulk.label = ""
        # If post
        if form.validate_on_submit():
            bulk_data = form.bulk.data
            form.bulk.label = "Targets Imported"
            log = self.do_bulk_import(bulk_data)  # Do the insert Job
            log = log + "\nEnd of import"
            form.bulk.data = log
            del form.submit

        results = []
        return self.render_template("bulk_targetsview.html", form=form, results=results)


class BotsView(ModelView):
    """
    This class implements the GUI for bots view
    """

    datamodel = SQLAInterface(Bots)
    list_columns = ["uid", "agent_version", "ip", "country", "last_seen"]


class JobsView(ModelView):
    """
    This class implements JOBs view
    """

    datamodel = SQLAInterface(Jobs)
    show_columns = [
        "uid",
        "scanprofile",
        "job_html",
        "scan_ports_html",
        "scan_nses_html",
        "bot_id",
        "job_creation",
        "job_start",
        "job_end",
        "targets_html",
        "active",
        "finished",
        "exported",
        "duration_html",
        "priority",
    ]
    list_columns = [
        "job_creation",
        "scanprofile",
        "job_start",
        "job_end",
        "job_summary_html",
        "targets_count_html",
        "active",
        "finished",
    ]
    edit_columns = ["targets", "active", "finished", "exported", "priority"]
    edit_form_extra_fields = {
        "priority": build_priority_field(),
    }
    base_order = ("job_creation", "desc")  # Latest finished on top.

    show_template = "show_jobview.html"  # Custom Show view with results
    list_template = "list_jobview.html"  # Custom Show view with results
    search_exclude_columns = ["targets"]
    label_columns = {
        "scanprofile": "Scan Profile",
        "job_html": "Scan Jobs",
        "job_summary_html": "Scan Jobs",
        "scan_ports_html": "Ports",
        "scan_nses_html": "NSE Scripts",
        "targets_html": "Targets",
        "targets_count_html": "Targets",
        "duration_html": "Duration",
    }

    @action(
        "mulraisepriority",
        "Priority Boost",
        "Raise Priority?",
        "fa-rocket",
        single=False,
    )
    def mulraiseprioriy(self, items):
        """
        Implement Raise priority of job to 2
        """
        if isinstance(items, list):
            # Raise N record
            for item in items:
                item.priority = 2
        else:
            # Raise Un tag
            items.priority = 2
        db.session.commit()
        self.update_redirect()
        return redirect(self.get_redirect())

    @action(
        "muldelete", "Delete Jobs", "Delete all Really?", "fa-trash-can", single=False
    )
    def muldelete(self, items):
        """
        Implement Multiple Delete for Targets
        """

        self.datamodel.delete_all(items)
        self.update_redirect()
        return redirect(self.get_redirect())

    def pre_update(self, item):
        normalize_priority(item)
        return self

    @expose("/file_get/<uid>")
    @has_access  # Tout authenticated people.
    def file_get(self, uid):
        """
        This methode will display a Json Result
        It will clean dead host
        """
        base = db.app.config.get("JSON_FOLDER")
        try:
            is_valid_uuid(uid)
            with open(f"{base}/{uid[0]}/{uid}.json", "rb") as file_handle:
                oobject = json.loads(file_handle.read())
        except (FileNotFoundError, ValueError):
            oobject = "{}"

        response = make_response(oobject)
        response.headers["Content-Type"] = "text/json"
        response.headers["Content-Disposition"] = "inline; filename={uid}.json"
        return response


class ApiKeysView(ModelView):
    """
    This class implements BOT tokens API's GUI
    """

    datamodel = SQLAInterface(ApiKeys)
    add_template = "add_apikeyview.html"  # Custom Add view with KeyGenerator
    list_columns = ["id", "description"]
    add_columns = ["key", "description"]
    edit_columns = ["description"]
    # show_columns = ["id", "description"]

    def pre_add(self, item):
        # Hash the KeyID and Keep the Index
        # 16 Char for ID :: 64 for password.
        item.keyidx = item.key[0:16]
        item.key = generate_password_hash(
            password=item.key,
            method=db.app.config.get("FAB_PASSWORD_HASH_METHOD", "scrypt"),
            salt_length=db.app.config.get("FAB_PASSWORD_HASH_SALT_LENGTH", 16),
        )
        return self


class NsesView(ModelView):
    """
    This class implements GUI for
    """

    datamodel = SQLAInterface(Nses)
    add_template = "add_nsesview.html"  # Custom Show view with results
    add_columns = ["filebody"]
    edit_columns = ["name", "hash", "replacement_file", "scanprofiles"]
    edit_form_extra_fields = {
        "replacement_file": FileField(
            "Replace NSE File",
            validators=[
                Optional(),
                FileAllowed(["nse"], "Only .nse files are allowed"),
            ],
        )
    }
    label_columns = {
        "filebody": "NSE File",
        "name": "Filename",
        "hash": "SHA256",
        "replacement_file": "Replace NSE File",
    }

    def _validate_nse_upload(self, upload):
        if not upload or not getattr(upload, "filename", ""):
            raise ValueError("An .nse file is required")

        filename = os.path.basename(upload.filename)
        if not filename.lower().endswith(".nse"):
            raise ValueError("Only .nse files are allowed")
        return upload, filename

    def _resolve_existing_nse(self, filename, sha256sum, current_id=None):
        match_by_hash = db.session.query(Nses).filter(Nses.hash == sha256sum).one_or_none()
        match_by_name = db.session.query(Nses).filter(Nses.name == filename).one_or_none()

        if current_id is not None:
            if match_by_hash is not None and match_by_hash.id == current_id:
                match_by_hash = None
            if match_by_name is not None and match_by_name.id == current_id:
                match_by_name = None

        if (
            match_by_hash is not None
            and match_by_name is not None
            and match_by_hash.id != match_by_name.id
        ):
            raise ValueError(
                "Upload conflict: this filename and this file hash match two different NSE entries"
            )

        return match_by_hash or match_by_name

    def _replace_nse_file(self, item, upload):
        upload, filename = self._validate_nse_upload(upload)
        file_bytes = upload.read()
        upload.stream.seek(0)
        sha256sum = hashlib.sha256(file_bytes).hexdigest()
        conflicting_item = self._resolve_existing_nse(filename, sha256sum, current_id=item.id)

        if conflicting_item is not None:
            raise ValueError(
                "Upload conflict: this filename or this file hash already belongs to another NSE entry"
            )

        file_manager = FileManager()
        if item.filebody:
            file_manager.delete_file(item.filebody)

        stored_name = file_manager.generate_name(item, upload)
        item.filebody = file_manager.save_file(upload, stored_name)
        item.name = filename
        item.hash = sha256sum

    def pre_update(self, item):
        replacement_file = getattr(item, "replacement_file", None)
        if replacement_file and getattr(replacement_file, "filename", ""):
            self._replace_nse_file(item, replacement_file)
        return self

    @expose("/add", methods=["GET", "POST"])
    @has_access
    def add(self):
        self.update_redirect()
        form = self.add_form.refresh()

        if request.method == "POST":
            if form.validate():
                self.process_form(form, True)
                try:
                    upload, filename = self._validate_nse_upload(form.filebody.data)
                    file_bytes = upload.read()
                    upload.stream.seek(0)
                    sha256sum = hashlib.sha256(file_bytes).hexdigest()
                    item = self._resolve_existing_nse(filename, sha256sum)
                    is_new = item is None
                    if is_new:
                        item = self.datamodel.obj()

                    item.name = filename
                    item.hash = sha256sum
                    form.populate_obj(item)

                    if is_new:
                        self.pre_add(item)
                        success = self.datamodel.add(item)
                    else:
                        self.pre_update(item)
                        success = self.datamodel.edit(item)
                        if success:
                            self.datamodel.message = ("NSE updated", "success")
                except Exception as e:
                    flash(str(e), "danger")
                else:
                    flash(*self.datamodel.message)
                    if success:
                        return redirect(url_for(f"{self.__class__.__name__}.list"))

        widgets = self._get_add_widget(form=form)
        return self.render_template(
            self.add_template, title=self.add_title, widgets=widgets
        )


class ScanprofilesView(ModelView):
    """
    This class implements GUI for
    """

    datamodel = SQLAInterface(ScanProfiles)
    add_template = "add_scanprofilesview.html"
    edit_template = "edit_scanprofilesview.html"
    list_template = "list_scanprofilesview.html"
    list_columns = {"name", "scan_cycle_minutes", "ports", "nses", "apply_to_all"}
    search_columns = ["name", "scan_cycle_minutes", "priority", "apply_to_all", "targets"]
    add_columns = ["name", "scan_cycle_minutes", "priority", "ports", "nses", "targets", "apply_to_all"]
    edit_columns = ["name", "scan_cycle_minutes", "priority", "ports", "nses", "targets", "apply_to_all"]
    show_columns = ["name", "scan_cycle_minutes", "priority", "ports", "nses", "targets", "apply_to_all"]
    search_form_extra_fields = {
        "targets": RemoteRelatedMultipleField(
            "Apply on Target",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="targets",
            endpoint="ScanprofilesView.targets_remote",
        )
    }
    add_form_extra_fields = {
        "priority": build_priority_field(),
        "ports": RemoteRelatedMultipleField(
            "Ports",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="ports",
            endpoint="ScanprofilesView.ports_remote",
        ),
        "nses": RemoteRelatedMultipleField(
            "Nse Scripts",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="nses",
            endpoint="ScanprofilesView.nses_remote",
        ),
        "targets": RemoteRelatedMultipleField(
            "Apply on Target",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="targets",
            endpoint="ScanprofilesView.targets_remote",
        )
    }
    edit_form_extra_fields = {
        "priority": build_priority_field(),
        "ports": RemoteRelatedMultipleField(
            "Ports",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="ports",
            endpoint="ScanprofilesView.ports_remote",
        ),
        "nses": RemoteRelatedMultipleField(
            "Nse Scripts",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="nses",
            endpoint="ScanprofilesView.nses_remote",
        ),
        "targets": RemoteRelatedMultipleField(
            "Apply on Target",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="targets",
            endpoint="ScanprofilesView.targets_remote",
        )
    }
    label_columns = {
        "nses": "Nse Scripts",
        "apply_to_all": "Apply to all scans",
        "targets": "Apply on Target",
        "scan_cycle_minutes": "Scan Frequency (min)",
    }

    def pre_add(self, item):
        normalize_priority(item)
        if len(item.ports) == 0:
            raise ValueError("At least one port is mandatory")
        if not item.scan_cycle_minutes or item.scan_cycle_minutes <= 0:
            raise ValueError("Scan frequency must be greater than 0 minute")
        return self

    def pre_update(self, item):
        normalize_priority(item)
        if len(item.ports) == 0:
            raise ValueError("At least one port is mandatory")
        if not item.scan_cycle_minutes or item.scan_cycle_minutes <= 0:
            raise ValueError("Scan frequency must be greater than 0 minute")
        return self

    @staticmethod
    def _remote_limit():
        try:
            return min(int(request.args.get("limit", 30)), 100)
        except (TypeError, ValueError):
            return 30

    @staticmethod
    def _remote_ids():
        raw_ids = []
        if request.args.get("ids"):
            raw_ids.extend(request.args.get("ids", "").split(","))
        raw_ids.extend(request.args.getlist("ids"))

        ids = []
        for raw_id in raw_ids:
            raw_id = str(raw_id).strip()
            if raw_id.isdigit():
                ids.append(int(raw_id))
        return list(dict.fromkeys(ids))

    @staticmethod
    def _json_results(items):
        return jsonify([{"id": item.id, "text": str(item)} for item in items])

    @expose("/ports_remote", methods=["GET"])
    @has_access
    def ports_remote(self):
        """
        AJAX endpoint for port lookup on scan profile forms.
        """
        query = request.args.get("q", "").strip()
        limit = self._remote_limit()
        selected_ids = self._remote_ids()

        if selected_ids:
            items = (
                db.session.query(Ports)
                .filter(Ports.id.in_(selected_ids))
                .order_by(Ports.value.asc())
                .all()
            )
            return self._json_results(items)

        if len(query) < 1:
            return jsonify([])

        filters = [
            Ports.name.ilike(f"%{query}%"),
            Ports.proto_to_port.ilike(f"%{query}%"),
        ]
        if query.isdigit():
            filters.append(Ports.value == int(query))

        items = (
            db.session.query(Ports)
            .filter(or_(*filters))
            .order_by(Ports.value.asc())
            .limit(limit)
            .all()
        )
        return self._json_results(items)

    @expose("/nses_remote", methods=["GET"])
    @has_access
    def nses_remote(self):
        """
        AJAX endpoint for NSE lookup on scan profile forms.
        """
        query = request.args.get("q", "").strip()
        limit = self._remote_limit()
        selected_ids = self._remote_ids()

        if selected_ids:
            items = (
                db.session.query(Nses)
                .filter(Nses.id.in_(selected_ids))
                .order_by(Nses.name.asc())
                .all()
            )
            return self._json_results(items)

        if len(query) < 1:
            return jsonify([])

        items = (
            db.session.query(Nses)
            .filter(or_(Nses.name.ilike(f"%{query}%"), Nses.hash.ilike(f"%{query}%")))
            .order_by(Nses.name.asc())
            .limit(limit)
            .all()
        )
        return self._json_results(items)

    @expose("/targets_remote", methods=["GET"])
    @has_access
    def targets_remote(self):
        """
        AJAX endpoint for target lookup on scan profile forms.
        """
        query = request.args.get("q", "").strip()
        limit = self._remote_limit()
        selected_ids = self._remote_ids()

        if selected_ids:
            items = (
                db.session.query(Targets)
                .filter(Targets.id.in_(selected_ids))
                .order_by(Targets.value.asc())
                .all()
            )
            return self._json_results(items)

        if len(query) < 1:
            return jsonify([])

        items = (
            db.session.query(Targets)
            .filter(
                or_(
                    Targets.value.ilike(f"%{query}%"),
                    Targets.description.ilike(f"%{query}%"),
                )
            )
            .order_by(Targets.value.asc())
            .limit(limit)
            .all()
        )
        return self._json_results(items)


class TargetScanStatesView(ModelView):
    """
    Status view for Target/Profile scan state.
    """

    datamodel = SQLAInterface(TargetScanStates)
    list_template = "list_targetscanstatesview.html"
    base_permissions = ["can_list", "can_show"]
    list_columns = ["target", "scanprofile", "working", "last_scan", "duration_html"]
    search_columns = ["target", "scanprofile", "working"]
    show_columns = [
        "target",
        "scanprofile",
        "working",
        "last_scan",
        "last_previous_scan",
        "duration_html",
    ]
    edit_columns = []
    add_columns = []
    base_order = ("last_scan", "desc")
    search_form_extra_fields = {
        "target": RemoteRelatedField(
            "Target",
            validators=[Optional()],
            datamodel=datamodel,
            col_name="target",
            endpoint="TargetScanStatesView.targets_remote",
        )
    }
    label_columns = {
        "target": "Target",
        "scanprofile": "Scan Profile",
        "last_scan": "Last Scan",
        "last_previous_scan": "Previous Scan",
        "duration_html": "Scan Cycle",
    }

    @staticmethod
    def _remote_limit():
        try:
            return min(int(request.args.get("limit", 30)), 100)
        except (TypeError, ValueError):
            return 30

    @staticmethod
    def _remote_ids():
        raw_ids = []
        if request.args.get("ids"):
            raw_ids.extend(request.args.get("ids", "").split(","))
        raw_ids.extend(request.args.getlist("ids"))

        ids = []
        for raw_id in raw_ids:
            raw_id = str(raw_id).strip()
            if raw_id.isdigit():
                ids.append(int(raw_id))
        return list(dict.fromkeys(ids))

    @staticmethod
    def _json_results(items):
        return jsonify([{"id": item.id, "text": str(item)} for item in items])

    @expose("/targets_remote", methods=["GET"])
    @has_access
    def targets_remote(self):
        """
        AJAX endpoint for target lookup on target scan state filters.
        """
        query = request.args.get("q", "").strip()
        limit = self._remote_limit()
        selected_ids = self._remote_ids()

        if selected_ids:
            items = (
                db.session.query(Targets)
                .filter(Targets.id.in_(selected_ids))
                .order_by(Targets.value.asc())
                .all()
            )
            return self._json_results(items)

        if len(query) < 1:
            return jsonify([])

        items = (
            db.session.query(Targets)
            .filter(
                or_(
                    Targets.value.ilike(f"%{query}%"),
                    Targets.description.ilike(f"%{query}%"),
                )
            )
            .order_by(Targets.value.asc())
            .limit(limit)
            .all()
        )
        return self._json_results(items)


class ProtosView(ModelView):
    """
    This class implements GUI for
    """

    datamodel = SQLAInterface(Protos)
    label_columns = {
        "value": "Protocol",
        "name": "Description",
    }
    list_columns = ["value", "name"]

    def pre_add(self, item):
        # Upper case protocol values
        item.value = item.value.upper()
        return self


class PortsView(ModelView):
    """
    This class implements GUI for
    """

    datamodel = SQLAInterface(Ports)
    label_columns = {
        "value": "Port",
        "name": "Description",
        "scanprofiles": "Scan Profiles",
        "proto": "Protocol",
    }
    list_columns = ["value", "proto", "name"]
    edit_columns = ["value", "proto", "name", "scanprofiles"]
    add_columns = ["value", "proto", "name", "scanprofiles"]
    base_order = ("value", "asc")  # Latest finished on top.

    def pre_add(self, item):
        # Create the tuple for proto_to_port to avoid port duplicate.
        item.proto_to_port = f"{item.proto}:{item.value}"
        return self


appbuilder.add_view(
    MeiliSearchView, "Token Search", icon="fa-magnifying-glass", category="Analytics"
)
appbuilder.add_view(
    KVSearchView, "Header Search", icon="fa-magnifying-glass", category="Analytics"
)
appbuilder.add_view_no_menu(IPDetailView)
appbuilder.add_view(
    ApiKeysView, name="", category=None
)  # See Security.py for additional conf.
appbuilder.add_view(TargetsView, "Targets", icon="fa-bullseye", category="Config")
appbuilder.add_link(
    "Bulk Import",
    href="/targetsview/bulk_import",
    category="Config",
    icon="fa-cart-arrow-down",
)
appbuilder.add_separator(category="Config")
appbuilder.add_view(
    ScanprofilesView, "Scan Profiles", icon="fa-folder-open-o", category="Config"
)
appbuilder.add_view(NsesView, "Nse Scripts", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(ProtosView, "Protocols", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(PortsView, "Ports", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(JobsView, "Jobs", icon="fa-chart-bar", category="Status")
appbuilder.add_view(
    TargetScanStatesView, "Profile Scans", icon="fa-chart-bar", category="Status"
)
appbuilder.add_view(BotsView, "Bots", icon="fa-folder-open-o", category="Status")
db.create_all()
