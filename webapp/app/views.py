"""
 .--. .-..-..-.                     .-.
: .--': :: :: :                     : :
: : _ : :: :: :       .--.  .--.  .-' : .--.
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
"""

import json
import shlex
import time
import logging
import os
import threading
import uuid
from datetime import datetime, timezone


from flask import render_template, redirect, make_response, send_file
from flask import request, jsonify
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView, action, has_access
from flask_appbuilder.api import expose
from flask_appbuilder import BaseView
from flask_login import current_user
from meilisearch import Client

from wtforms import TextAreaField, SubmitField
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from app import app
from .models import Bots, Targets, Jobs, ApiKeys, Nses, Protos, ScanProfiles, Ports
from .utils.mutils import is_valid_uuid, is_valid_ip, is_valid_cidr
from .utils.mutils import is_valid_ip_or_cidr, is_valid_fqdn, lowercase_dict
from .utils.kvrocks import KVrocksIndexer
from .utils.ip2asn import get_asn_description_for_ip


from . import appbuilder, db

logger = logging.getLogger("flask_appbuilder")
EXPORT_JOB_STATES = {}
EXPORT_JOB_STATES_LOCK = threading.Lock()


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


# Add a Functions to jinja
app.jinja_env.globals["get_job_uid"] = get_job_uid
app.jinja_env.globals["get_target_value"] = get_target_value


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
            "generated_at": datetime.now(timezone.utc).isoformat(),
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
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as error:
                logger.exception("Full export job %s failed", job_id)
                KVSearchView._set_job_state(
                    job_id,
                    status="error",
                    error=str(error),
                )

    def parse_query(self, query):
        """
        This function parse the query string.
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

    def execute_search(self, query):
        """
        Shared search executor used by both JSON and export endpoints.
        """
        start_time = time.time()
        query = query or ""
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        criteria, status, msg_error = self.parse_query(query)
        count_objects = indexer.objects_count()  # Get object count in db
        results_ip = {}
        timestamp_array = {}

        if status:
            criteria = lowercase_dict(criteria)
            logger.debug(criteria)
            uids = indexer.get_uids_by_criteria(criteria)
            results_ip = indexer.get_ip_from_uids(uids)

            for ip in results_ip:
                timestamp_array[ip] = indexer.get_timestamp_for_ip(ip)

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
    list_columns = ["value", "description", "last_scan", "active", "working"]
    label_columns = {
        "value": "CIDR/Host",
        "scanprofiles": "Scan profiles",
        "duration_html": "Scan Cycle",
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
        "job_html",
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
        "job_start",
        "job_end",
        "job_html",
        "targets_html",
        "active",
        "finished",
    ]
    edit_columns = ["targets", "active", "finished", "exported", "priority"]
    base_order = ("job_creation", "desc")  # Latest finished on top.

    show_template = "show_jobview.html"  # Custom Show view with results
    list_template = "list_jobview.html"  # Custom Show view with results
    search_exclude_columns = ["targets"]
    label_columns = {
        "job_html": "Scan Jobs",
        "targets_html": "Targets",
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


class ScanprofilesView(ModelView):
    """
    This class implements GUI for
    """

    datamodel = SQLAInterface(ScanProfiles)
    list_columns = {"name", "ports", "nses", "apply_to_all"}
    label_columns = {
        "nses": "Nse Scripts",
        "apply_to_all": "Apply to all scans",
        "targets": "Apply on Target",
    }

    def pre_add(self, item):
        if len(item.ports) == 0:
            raise ValueError("At least one port is mandatory")
        return self


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
appbuilder.add_view(BotsView, "Bots", icon="fa-folder-open-o", category="Status")
db.create_all()
