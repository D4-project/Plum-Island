"""
 .--. .-..-..-.                     .-.
: .--': :: :: :                     : :
: : _ : :: :: :       .--.  .--.  .-' : .--.
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
"""

import hashlib
import json
import shlex
import time
import logging
import os
import threading
import uuid


from flask import render_template, redirect, make_response, send_file, flash, url_for
from flask import request, jsonify
from markupsafe import Markup, escape
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView, action, has_access
from flask_appbuilder.api import expose
from flask_appbuilder import BaseView
from flask_login import current_user
from meilisearch import Client

from wtforms import TextAreaField, SubmitField, Field, ValidationError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_appbuilder.filemanager import FileManager
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from wtforms.validators import Optional
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
            "query": job_state["query"],
            "processed_uids": job_state["processed_uids"],
            "total_uids": job_state["total_uids"],
            "progress_percent": job_state["progress_percent"],
            "elapsed_seconds": elapsed_seconds,
            "download_ready": bool(job_state["file_path"])
            and job_state["status"] == "done",
            "error": job_state["error"],
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
            "generated_at": utcnow_iso(),
            "results": {},
        }

        total_uids = sum(len(uids) for uids in results["results"].values())
        return export_payload, index, total_uids

    @staticmethod
    def _run_full_export_job(job_id):
        with app.app_context():
            job_state = KVSearchView._get_job_state(job_id)
            if not job_state:
                return

            query = job_state["query"]
            results = KVSearchView().execute_search(query)
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
                        result = index.get_document(uid)
                        export_payload["results"][ip].append(
                            {
                                "uid": uid,
                                "first_seen": ip_timestamps.get(uid, {}).get(
                                    "first_seen"
                                ),
                                "last_seen": ip_timestamps.get(uid, {}).get(
                                    "last_seen"
                                ),
                                "document": vars(result),
                            }
                        )
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

    def split_query_groups(self, query):
        """
        Split a query into AND groups separated by explicit OR tokens.
        """
        parts = shlex.split(query or "")
        if not parts:
            return [""]

        groups = []
        current_group = []
        for part in parts:
            if part.upper() == "OR":
                groups.append(" ".join(current_group))
                current_group = []
            else:
                current_group.append(part)
        groups.append(" ".join(current_group))
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
            "host",
            "domain",
            "tld",
            # "url_path",
            "port",
            # "protocol",
            "http_title",
            # "http_favicon_hash",
            # "http_favicon_sha256",
            # "http_favicon_sha1",
            # "http_favicon",
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
        parts = shlex.split(query)
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
        query_groups = self.split_query_groups(query)
        parsed_groups = []
        error_messages = []

        for idx, group in enumerate(query_groups, start=1):
            if not group.strip():
                error_messages.append(f"Empty query group around OR at segment {idx}")
                continue

            criteria, status, msg_error = self.parse_query_group(group)
            if not status:
                error_messages.append(msg_error or f"Invalid query group {idx}")
                continue
            parsed_groups.append(criteria)

        status = len(error_messages) == 0
        return parsed_groups, status, " | ".join(error_messages)

    def execute_search(self, query):
        """
        Shared search executor used by both JSON and export endpoints.
        """
        start_time = time.time()
        query = query or ""
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        criteria_groups, status, msg_error = self.parse_query(query)
        count_objects = indexer.objects_count()  # Get object count in db
        results_ip = {}
        timestamp_array = {}

        if status:
            merged_ip_map = {}
            for criteria in criteria_groups:
                criteria = lowercase_dict(criteria)
                logger.debug(criteria)
                uids = indexer.get_uids_by_criteria(criteria)
                group_ip_map = indexer.get_ip_from_uids(uids)

                for ip, group_uids in group_ip_map.items():
                    if ip not in merged_ip_map:
                        merged_ip_map[ip] = []
                    for uid in group_uids:
                        if uid not in merged_ip_map[ip]:
                            merged_ip_map[ip].append(uid)

            results_ip = merged_ip_map

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

        end_time = time.time()
        processingtimems = (end_time - start_time) * 1000

        return {
            "status": status,
            "results": results_ip if status else {},
            "timestamps": timestamp_array if status else {},
            "msg_error": msg_error or "",
            "processingTimeMs": processingtimems,
            "uid_count": count_objects.get("uid_count"),
            "ip_count": count_objects.get("ip_count"),
        }

    @expose("/query")
    @has_access
    def query(self):
        """
        This Function send the query back to KVRocks
        """
        query = request.args.get("q", "")
        results = self.execute_search(query)
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

        results = self.execute_search(query)
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

        job_id = str(uuid.uuid4())
        owner_user_id = getattr(current_user, "id", None)
        owner_username = getattr(current_user, "username", "")
        with EXPORT_JOB_STATES_LOCK:
            EXPORT_JOB_STATES[job_id] = {
                "job_id": job_id,
                "owner_user_id": owner_user_id,
                "owner_username": owner_username,
                "status": "queued",
                "query": query,
                "created_ts": time.time(),
                "processed_uids": 0,
                "total_uids": 0,
                "progress_percent": 0.0,
                "file_path": None,
                "error": "",
                "finished_at": None,
            }

        worker = threading.Thread(
            target=self._run_full_export_job,
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

    @expose("/search")
    def search(self):
        """
        This fuction display the search page
        """
        return self.render_template("search_kvrocks.html")


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
            file = open(f"{base}/{uid[0]}/{uid}.json", "rb")
            oobject = json.loads(file.read())
            file.close()
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
        is_valid_form = True
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
                is_valid_form = False
            else:
                is_valid_form = False

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
        if len(item.ports) == 0:
            raise ValueError("At least one port is mandatory")
        if not item.scan_cycle_minutes or item.scan_cycle_minutes <= 0:
            raise ValueError("Scan frequency must be greater than 0 minute")
        return self

    def pre_update(self, item):
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
