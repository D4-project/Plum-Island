'''
 .--. .---. .-.                     .-.      
: .; :: .; :: :                     : :      
:    ::  _.': :       .--.  .--.  .-' : .--. 
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
'''

from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi, BaseView
from flask_appbuilder.api import expose
from flask import jsonify
from .models import Targets
from . import appbuilder

class PublicTargetsApi(ModelRestApi):
    '''
    This class implement the API access for the Target definition
    '''
    datamodel = SQLAInterface(Targets)

class Api(BaseView):
    '''
    This class implement all interactions with the BOTS.
    '''
    route_base = "/bot_api"

    @expose('/register', methods=['GET'])
    def beacon(self):
        '''
        This function implement bot registration.
        '''
        return jsonify({"message": "Im Happy"})

appbuilder.add_api(Api())
appbuilder.add_api(PublicTargetsApi)
