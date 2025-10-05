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

app = Flask(__name__)
app.config.from_object("config")
db = SQLA(app)

"""
from sqlalchemy.engine import Engine
from sqlalchemy import event

#Only include this for SQLLite constraints
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    # Will force sqllite contraint foreign keys
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
"""

appbuilder = AppBuilder(app, db.session, security_manager_class=CustomSecurityManager)

# pylint: disable=C0413
from . import views  # Includes the GUI code
from . import apis  # Includes the API code

"""
Init module for Flask AppBuilder application
"""

import logging
from flask import Flask
from flask_appbuilder import AppBuilder, SQLA
from .security import CustomSecurityManager  # Custom Security menu

# Logging configuration
logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)

# Flask + SQLAlchemy
app = Flask(__name__)
app.config.from_object("config")
db = SQLA(app)
appbuilder = AppBuilder(app, db.session, security_manager_class=CustomSecurityManager)

# Import views and APIs
from . import views
from . import apis

# Scheduler: should only start in main process once
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    # Import scheduler here so it runs only in the main process
    from . import scheduler

    logging.debug("Scheduler Imported")
