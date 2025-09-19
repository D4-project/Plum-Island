'''

 .--. .-..-..-.                     .-.      
: .--': :: :: :                     : :      
: : _ : :: :: :       .--.  .--.  .-' : .--. 
: :; :: :; :: :      '  ..'' .; :' .; :' '_.'
`.__.'`.__.':_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to the GUI.
'''

from flask import render_template
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelView
from .models import Bots, Targets, Jobs, ApiKeys
from . import appbuilder, db

@appbuilder.app.errorhandler(404)
def page_not_found(e):
    '''
    Application wide 404 error handler
    '''
    _ = e
    return (
        render_template(
            "404.html", base_template=appbuilder.base_template, appbuilder=appbuilder
        ),
        404,
    )

class TargetsView(ModelView):
    '''
    This class implements the GUI for targets
    '''
    datamodel = SQLAInterface(Targets)
    list_columns = ['value','description','active']
    label_columns = {'value': 'CIDR/Host'}
    base_order = ('value', 'desc')

class BotsView(ModelView):
    '''
    This class implements the GUI for bots view
    '''
    datamodel = SQLAInterface(Bots)

class JobsView(ModelView):
    '''
    This class implements JOBs view
    '''
    datamodel = SQLAInterface(Jobs)

class ApiKeysView(ModelView):
    '''
    This class implements BOT tokens API's GUI 
    '''
    datamodel = SQLAInterface(ApiKeys)


appbuilder.add_view( ApiKeysView, name="", category=None ) # See Security.py for additional conf.
appbuilder.add_view( TargetsView, "Targets", icon="fa-folder-open-o", category="Config" )
appbuilder.add_view( BotsView, "Bots", icon="fa-folder-open-o", category="Config" )
appbuilder.add_view( JobsView, "Jobs", icon="fa-folder-open-o", category="Status" )
db.create_all()
