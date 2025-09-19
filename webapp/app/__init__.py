'''

This is the init module of the flask appbuilder application.
'''


import logging

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

# from .security import CustomSecurityManager  # Custom Security menu
appbuilder = AppBuilder(app, db.session, security_manager_class=CustomSecurityManager)

# pylint: disable=C0413
from . import views  # Includes the GUI code
from . import apis   # Includes the API code
