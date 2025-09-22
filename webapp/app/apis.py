"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi
from flask_appbuilder.api import BaseApi, expose, safe
from flask import request

from marshmallow import Schema, fields, ValidationError
from .models import Targets
from . import appbuilder
import logging


class BotInfoSchema(Schema):
    UID = fields.String(
        required=True, metadata={"description": "Identifiant unique du bot"}
    )
    DEVICE_MODEL = fields.String(
        required=False, metadata={"description": "Modèle du périphérique"}
    )
    AGENT_VERSION = fields.String(
        required=False, metadata={"description": "Version de l'agent du bot"}
    )
    SYSTEM_VERSION = fields.String(
        required=False, metadata={"description": "Version du système d'exploitation"}
    )
    EXT_IP = fields.String(
        required=False, metadata={"description": "Adresse IP externe du bot"}
    )


class StatusInputSchema(Schema):
    botinfo = fields.Nested(
        BotInfoSchema, required=True, metadata={"description": "Informations du bot"}
    )


logger = logging.getLogger("flask_appbuilder")


class PublicTargetsApi(ModelRestApi):
    """
    This class implement the API access for the Target definition
    """

    datamodel = SQLAInterface(Targets)


class Api(BaseApi):
    """
    This class implements all interactions with the BOTS.
    """

    route_base = "/bot_api"
    openapi_spec_tag = "Bots API"

    @expose("/beacon", methods=["GET"])
    @safe
    def beacon(self):
        """
        This function implements bot registration.
        """
        return self.response(200, message="I'm Happy")

    @expose("/status", methods=["POST"])
    @safe
    def status(self):
        """
        Bot to Island connection health check
        """

        try:
            data = request.get_json(force=True)
            # schema = StatusInputSchema()
            # data = schema.load(json_data)
            data = data.loads(data)
        except ValidationError as err:
            return self.response_400(message="Invalid input")  # , errors=err.messages)
        except Exception:
            return self.response_400(message="Malformed JSON")

        print(data)
        print(type(data))
        botinfo = data.get("botinfo")
        uid = botinfo.get("UID")

        logger.debug("UID %s Home check", uid)
        return self.response(200, message="ready")


# appbuilder.add_view(Api, "API", category="API")
appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(Api)
