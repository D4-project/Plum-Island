"""
This is the init module of the flask appbuilder application.
"""

import logging
import os
import sqlite3
from flask import Flask
from flask_appbuilder import AppBuilder, SQLA
from sqlalchemy import event
from sqlalchemy.engine import Engine
from .security import CustomSecurityManager  # Custom Security menu

# Loggin configuration
logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)

# Flask + SQLAlchemy
app = Flask(__name__)
app.config.from_object("config")


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

# Scheduler: should only start in main process once
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    # Import scheduler here so it runs only in the main process
    from . import scheduler

    logging.debug("Scheduler Imported")
