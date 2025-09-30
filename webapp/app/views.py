"""

 .--. .-..-..-.                     .-.
: .--': :: :: :                     : :
: : _ : :: :: :       .--.  .--.  .-' : .--.
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
"""

import json
from flask import render_template, redirect, make_response
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView, action, has_access
from flask_appbuilder.api import expose
from werkzeug.security import generate_password_hash
from app import app
from .models import Bots, Targets, Jobs, ApiKeys, Nses, Protos, ScanProfiles, Ports
from .utils.mutils import is_valid_uuid
from . import appbuilder, db


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


class TargetsView(ModelView):
    """
    This class implements the GUI for targets
    """

    datamodel = SQLAInterface(Targets)
    list_columns = ["value", "description", "active", "working"]
    label_columns = {"value": "CIDR/Host", "scanprofiles": "Scan profiles"}
    base_order = ("value", "desc")
    add_columns = ["value", "description", "active", "scanprofiles"]
    edit_columns = ["value", "description", "active", "working", "scanprofiles"]
    search_exclude_columns = ["jobs"]

    @action("muldelete", "Delete", "Delete all Really?", "fa-rocket", single=False)
    def muldelete(self, items):
        """
        Implement Multiple Delete for Targets
        """

        self.datamodel.delete_all(items)
        self.update_redirect()
        return redirect(self.get_redirect())


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
        "job",
        "bot_id",
        "job_start",
        "job_end",
        "targets",
        "active",
        "finished",
    ]
    list_columns = [
        "job",
        "job_start",
        "job_end",
        "targets",
        "active",
        "finished",
    ]
    edit_columns = [
        "targets",
        "active",
        "finished",
    ]
    base_order = ("job_end", "desc")  # Latest finished on top.

    show_template = "show_jobview.html"  # Custom Show view with results
    search_exclude_columns = ["targets"]

    @action("muldelete", "Delete", "Delete all Really?", "fa-rocket", single=False)
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
            file = open(f"{base}/{uid}.json", "rb")
            oobject = json.loads(file.read())
            file.close()
        except (FileNotFoundError, ValueError):
            oobject = "{}"

        cobject = []
        for item in oobject:
            if item.get("host_reply") == True:
                cobject.append(item)

        response = make_response(cobject)
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
            print("raise")
            raise ValueError("At least one port is madatory")
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
    ApiKeysView, name="", category=None
)  # See Security.py for additional conf.
appbuilder.add_view(TargetsView, "Targets", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(BotsView, "Bots", icon="fa-folder-open-o", category="Config")
appbuilder.add_separator(category="Config")
appbuilder.add_view(
    ScanprofilesView, "Scan Profiles", icon="fa-folder-open-o", category="Config"
)
appbuilder.add_view(NsesView, "Nse Scripts", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(ProtosView, "Protocols", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(PortsView, "Ports", icon="fa-folder-open-o", category="Config")

appbuilder.add_view(JobsView, "Jobs", icon="fa-folder-open-o", category="Status")
db.create_all()
