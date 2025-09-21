"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi, BaseView
from flask_appbuilder.api import expose
from flask import jsonify, request
from .models import Targets
from . import appbuilder
import json
import logging

logger = logging.getLogger("flask_appbuilder")


class PublicTargetsApi(ModelRestApi):
    """
    This class implement the API access for the Target definition
    """

    datamodel = SQLAInterface(Targets)


class Api(BaseView):
    """
    This class implement all interactions with the BOTS.
    """

    route_base = "/bot_api"

    @expose("/beacon", methods=["GET"])
    def beacon(self):
        """
        This function implement bot registration.
        """
        return jsonify({"message": "Im Happy"})

    @expose("/status", methods=["POST"])
    def status(self):
        """
        Bot to Island connection health check
        """
        try:
            data = request.get_json(force=True)
            data = json.loads(data)
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400

        if data is None or data.get("botinfo") is None:
            return jsonify({"error": "Missing JSON"}), 400

        botinfo = data.get("botinfo")
        if not botinfo.get("UID"):
            return jsonify({"error": "Missing bot_id"}), 400
        logger.debug("UID %s Home check", botinfo.get("UID"))

        return jsonify({"message": "ready"})


appbuilder.add_view(Api, "API", category="API")
appbuilder.add_api(PublicTargetsApi)
