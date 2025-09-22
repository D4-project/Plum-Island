"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

from datetime import datetime, timezone
import json
import logging
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi
from flask_appbuilder.api import BaseApi, expose, safe
from flask import request

from sqlalchemy.exc import IntegrityError

from marshmallow import Schema, fields, validates, ValidationError
from .models import Targets, Bots, ApiKeys
from . import appbuilder, db
from .utils.mutils import is_valid_uuid, is_valid_ip, get_country, flat_marsh_error


class BotInfoSchema(Schema):
    """
    Schema for the BOT beaconing query
    """

    UID = fields.String(required=True, metadata={"description": "Uniq Bot ID"})
    DEVICE_MODEL = fields.String(
        required=True,
        metadata={"description": "Bot Python version"},
    )
    AGENT_VERSION = fields.String(
        required=True,
        metadata={"description": "Plum Agent Version"},
    )
    SYSTEM_VERSION = fields.String(
        required=True,
        metadata={"description": "Operating System Version"},
    )
    EXT_IP = fields.String(
        required=True,
        metadata={"description": "Last external IP"},
    )
    API_KEY = fields.String(
        required=True,
        metadata={"description": "Bot Agent access Key"},
    )

    # Custom validator for the parameters
    @validates("UID")
    def validate_uid(self, value, **kwargs):
        """
        UID Validation
        """
        if len(value) != 36:
            raise ValidationError("Invalid UID")
        if not is_valid_uuid(value):
            raise ValidationError("Invalid UID")
        return True

    @validates("EXT_IP")
    def validate_ext_ip(self, value, **kwargs):
        """
        IP Validation
        """
        if not is_valid_ip(value):
            raise ValidationError("Invalid IP")
        return True

    @validates("API_KEY")
    def validate_api_key(self, value, **kwargs):
        """
        Validate Authorization to interact with Island
        """
        if len(value) != 64:  # Avoid SQL query or Hash with funky data
            raise ValidationError("Invalid Key")
        if db.session.query(ApiKeys).filter_by(key=value).scalar():
            return True  # La clef Existe
        raise ValidationError("Invalid Key")


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

    @expose("/beacon", methods=["POST"])
    @safe
    def status(self):
        """
        Bot to Island connection health check

        Example;
        curl -X POST \
            http://localhost:5000/bot_api/beacon \
            -H 'Content-Type: application/json' \
            -d '{"DEVICE_MODEL": "CPython 3.12.3", "AGENT_VERSION": "untagged-ef62e24", \
            "SYSTEM_VERSION": "Linux 6.14.0-27-generic", "UID": "75a04e87-a740-4c75-9096-add9ec13baf5", \
            "EXT_IP": 203.0.113.128"}'
        """

        try:
            data = request.get_json(force=True)
            if not isinstance(data, dict):
                data = json.loads(
                    data
                )  # Convert to Dict (for content type missing requests)

            botinfoschema = BotInfoSchema()
            botinfo = botinfoschema.load(
                data,
            )  # Validate Request data and format

        except ValidationError as err:
            return self.response_400(
                message=f"Invalid input: {flat_marsh_error(err.messages)}"
            )

        logger.debug("UID %s Beacon", botinfo.get("UID"))

        new_bot = Bots(
            # Last Seen is autoupdated at creation
            uid=botinfo.get("UID"),
            ip=botinfo.get("EXT_IP"),
            country=get_country(botinfo.get("EXT_IP")),
            device_model=botinfo.get("DEVICE_MODEL"),
            agent_version=botinfo.get("AGENT_VERSION"),
            system_version=botinfo.get("SYSTEM_VERSION"),
        )

        db.session.add(new_bot)
        try:
            db.session.commit()
            return self.response(200, message="ready")
        except IntegrityError:
            db.session.rollback()
            db.session.query(Bots).filter_by(uid=botinfo.get("UID")).update(
                {
                    Bots.last_seen: datetime.now(timezone.utc),
                    Bots.ip: botinfo.get("EXT_IP"),
                },
                synchronize_session="fetch",
            )  # 'fetch' So SQLAlchemy keep correct session state
            db.session.commit()
            return self.response(200, message="ready")


appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(Api)
