"""
This is the init module of the flask appbuilder application.
"""

import logging
import os
import sqlite3
from flask import Flask, g
from flask_appbuilder import AppBuilder, SQLA
from sqlalchemy import event
from sqlalchemy.engine import Engine
from plum_settings import apply_settings
from .security import CustomSecurityManager  # Custom Security menu
from .logging_config import configure_logging
from .ui_theme import configure_ui_templates
from .ui_assets import configure_icon_assets
from .utils.index_generations import READER_SCOPE

# Flask + SQLAlchemy
app = Flask(__name__)
app.config.from_object("config")
apply_settings(app.config)
configure_ui_templates(app)
configure_icon_assets(app)


@app.before_request
def pin_request_index():
    """All structured reads within a request share the same index generation."""
    g.index_generation_token = READER_SCOPE.set({})


@app.teardown_request
def release_request_index(_error=None):
    """Release the context without deleting generations used by other readers."""
    token = g.pop("index_generation_token", None)
    if token is not None:
        READER_SCOPE.reset(token)


# AppBuilder's static blueprint otherwise looks only in its packaged themes.
app.add_url_rule(
    "/static/appbuilder/css/themes/plum.css",
    endpoint="plum_theme",
    view_func=app.send_static_file,
    defaults={"filename": "appbuilder/css/themes/plum.css"},
)
app.add_url_rule(
    "/static/appbuilder/css/themes/plum-components.css",
    endpoint="plum_theme_components",
    view_func=app.send_static_file,
    defaults={"filename": "appbuilder/css/themes/plum-components.css"},
)
logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
configure_logging(app.config)


@event.listens_for(Engine, "connect")
def configure_sqlite_connection(dbapi_connection, connection_record):
    """
    Reduce SQLite lock errors when the background scheduler writes concurrently.
    """
    _ = connection_record
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return

    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def prepare_export_jobs_folder(export_jobs_folder):
    """
    Ensure the export jobs directory exists on app boot.
    """
    os.makedirs(export_jobs_folder, exist_ok=True)


prepare_export_jobs_folder(app.config["EXPORT_JOBS_FOLDER"])

db = SQLA(app)
appbuilder = AppBuilder(app, db.session, security_manager_class=CustomSecurityManager)

# Import views and APIs
# pylint: disable=C0413
from . import views
from . import apis
from .settings_view import PlumSettingsView

appbuilder.add_view(
    PlumSettingsView,
    "Plum Settings",
    category="Security",
    icon="fa-sliders",
    menu_cond=appbuilder.sm.is_plum_settings_admin,
)

# Scheduler: should only start in main process once
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    # Import scheduler here so it runs only in the main process
    from . import scheduler

    logging.debug("Scheduler Imported")
