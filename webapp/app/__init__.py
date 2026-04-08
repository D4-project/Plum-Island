"""
This is the init module of the flask appbuilder application.
"""

import logging
import os
from flask import Flask
from flask_appbuilder import AppBuilder, SQLA
from .security import CustomSecurityManager  # Custom Security menu

# Loggin configuration
logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)

# Flask + SQLAlchemy
app = Flask(__name__)
app.config.from_object("config")


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
