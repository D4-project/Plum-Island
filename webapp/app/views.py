"""

 .--. .-..-..-.                     .-.
: .--': :: :: :                     : :
: : _ : :: :: :       .--.  .--.  .-' : .--.
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
"""

from flask import render_template
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView
from werkzeug.security import generate_password_hash
from .models import Bots, Targets, Jobs, ApiKeys
from . import appbuilder, db


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
    list_columns = ["value", "description", "active"]
    label_columns = {"value": "CIDR/Host"}
    base_order = ("value", "desc")


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


class ApiKeysView(ModelView):
    """
    This class implements BOT tokens API's GUI
    """

    datamodel = SQLAInterface(ApiKeys)
    add_template = "add_apikeyview.html"  # Custom Add view with KeyGenerator
    list_columns = ["id", "description"]
    edit_columns = ["description"]
    show_columns = ["id", "description"]

    def pre_add(self, item):
        print(item.key)
        keyid = key[0:16]
        print(keyid)
        password = generate_password_hash(
            password=item.key,
            method=db.app.config.get("FAB_PASSWORD_HASH_METHOD", "scrypt"),
            salt_length=db.app.config.get("FAB_PASSWORD_HASH_SALT_LENGTH", 16),
        )
        print(password)


appbuilder.add_view(
    ApiKeysView, name="", category=None
)  # See Security.py for additional conf.
appbuilder.add_view(TargetsView, "Targets", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(BotsView, "Bots", icon="fa-folder-open-o", category="Config")
appbuilder.add_view(JobsView, "Jobs", icon="fa-folder-open-o", category="Status")
db.create_all()
