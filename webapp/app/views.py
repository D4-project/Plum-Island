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


from flask import render_template, redirect, make_response
from flask import request, jsonify
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView, action, has_access
from flask_appbuilder.api import expose
from flask_appbuilder import BaseView
from meilisearch import Client

from wtforms import TextAreaField, SubmitField
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from app import app
from .models import Bots, Targets, Jobs, ApiKeys, Nses, Protos, ScanProfiles, Ports
from .utils.mutils import is_valid_uuid, is_valid_ip, is_valid_cidr
from .utils.mutils import is_valid_ip_or_cidr, is_valid_fqdn
from .utils.kvrocks import KVrocksIndexer
from .utils.ip2asn import get_asn_description_for_ip


from . import appbuilder, db

logger = logging.getLogger("flask_appbuilder")


def get_job_uid(pk):
    """
    For Jinja and ajax queries, get a UID from ID
    """
    result = db.session.query(Jobs.uid).filter(Jobs.id == pk).scalar()
    return result


# Add a Functions to jinja
app.jinja_env.globals["get_job_uid"] = get_job_uid


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
    """

    default_view = "search"

    def parse_query(self, query):
        """
        This function parse the query string.
        It validate if we got a good syntax and use only authorised keyywords.

        """

        valid_keywords = {
            "http_server",
            "http_cookie",
            "http_title",
            "ip",
            "net",
            "port",
        }

        valid_modifiers = {".lk", ".like", ".bg", ".begin", ".not", ".nt"}

        result = {}
        msg_error = None
        parts = shlex.split(query)
        for part in parts:
            if ":" not in part:
                msg_error = f"Bad keyword/value: {part}"
                continue

            key, value = part.split(":", 1)

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

    @expose("/query")
    def query(self):
        """
        This Function send the query back to KVRocks
        """
        start_time = time.time()
        query = request.args.get("q", "")
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        criteria, status, msg_error = self.parse_query(query)
        count_objects = indexer.objects_count()

        uids = indexer.get_uids_by_criteria(criteria)
        results_ip = indexer.get_ip_from_uids(uids)

        end_time = time.time()
        processingtimems = (end_time - start_time) * 1000
        if status is True:
            logger.debug(criteria)
            results = {
                "status": True,
                "results": results_ip,
                "msg_error": "",
                "processingTimeMs": processingtimems,
                "uid_count": count_objects.get("uid_count"),
                "ip_count": count_objects.get("ip_count"),
            }
        else:
            results = {
                "status": False,
                "results": {},
                "msg_error": msg_error,
                "processingTimeMs": processingtimems,
                "uid_count": count_objects.get("uid_count"),
                "ip_count": count_objects.get("ip_count"),
            }
        return jsonify(results)

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

    @expose("/custom_action/<int:pk>")
    def custom_action(self, pk):
        item = self.datamodel.get(pk)
        item.name = item.name.upper()
        self.datamodel.session.commit()
        flash(f"Action applied on {item.name}")
        return redirect(self.get_redirect())

    def do_bulk_import(self, ips):
        """
        Import a list of bulk Ip's into the targets"""
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
            log = TargetsView.do_bulk_import(self, bulk_data)  # Do the insert Job
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
