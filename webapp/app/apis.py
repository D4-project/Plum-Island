"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

import os
from datetime import datetime, timezone
import json
import logging
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi
from flask_appbuilder.api import BaseApi, expose, safe
from flask import request

from sqlalchemy import func, distinct
from sqlalchemy.exc import IntegrityError, NoResultFound
from werkzeug.security import check_password_hash
from marshmallow import Schema, fields, validates, ValidationError
from .models import Targets, Bots, ApiKeys, Jobs, assoc_jobs_targets
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
    AGENT_KEY = fields.String(
        required=True,
        metadata={"description": "Bot Agent access Key"},
    )
    RESULT = fields.String(
        required=False,
        metadata={"description": "Result of scan"},
    )
    JOB_UID = fields.String(
        required=False,
        metadata={"description": "Uid of the scan"},
    )

    # Custom validator for the parameters
    @validates("UID")
    @validates("JOB_UID")
    def validate_uid(self, value, data_key):
        """
        UID Validation
        """
        if len(value) != 36:
            raise ValidationError(f"Invalid {data_key}")
        if not is_valid_uuid(value):
            raise ValidationError(f"Invalid {data_key}")
        return True

    @validates("EXT_IP")
    def validate_ext_ip(self, value, data_key):
        """
        IP Validation
        """
        if not is_valid_ip(value):  # Validate that IP is a public one.
            raise ValidationError(f"Invalid {data_key}")
        return True

    @validates("AGENT_KEY")
    def validate_agent_key(self, value, data_key):
        """
        Validate Authorization to interact with Island
        """
        if len(value) != 16 + 64:  # Avoid SQL query or Hashing with funky data
            raise ValidationError("Invalid Agent Key")

        keyidx = value[0:16]  # Get the entry for the ciphered pass
        try:
            agentkey = (
                db.session.query(ApiKeys).filter(ApiKeys.keyidx == keyidx).one().key
            )
            if check_password_hash(agentkey, value):
                return True  # If the key is existing
        except NoResultFound as error:
            raise ValidationError(f"Invalid {data_key}") from error
        raise ValidationError(f"Invalid {data_key}")


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
            "EXT_IP": 203.0.113.128", "AGENT_KEY": "REPLACEWITHKEY"}'
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
            # We Update bot info, IP / Last Seen at each beacon.
            db.session.rollback()
            db.session.query(Bots).filter_by(uid=botinfo.get("UID")).update(
                {
                    Bots.last_seen: datetime.now(timezone.utc),
                    Bots.ip: botinfo.get("EXT_IP"),
                    Bots.device_model: botinfo.get("DEVICE_MODEL"),
                    Bots.agent_version: botinfo.get("AGENT_VERSION"),
                    Bots.system_version: botinfo.get("SYSTEM_VERSION"),
                },
                synchronize_session="fetch",
            )  # 'fetch' So SQLAlchemy keep correct session state
            db.session.commit()
            return self.response(200, message="ready")

    @expose("/getjob", methods=["POST"])
    @safe
    def getjobs(self):
        """
        Bot to Island connection to fetch new a scanning job .

        Return a JobTodo.
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

        logger.debug("Agent UID %s Requesting a JOB", botinfo.get("UID"))

        # Get the BOT object from DB
        job_bot = (
            db.session.query(Bots)
            .filter(Bots.uid == botinfo.get("UID"))
            .limit("1")
            .scalar()
        )

        # Get one Job todo
        job_todo = (
            db.session.query(Jobs)
            .filter(Jobs.active == False, Jobs.finished == False)
            .order_by(Jobs.job_creation.asc())  # Get all waiting jobs, oldest first
            .first()  # get one Job object
        )

        if job_todo:
            job_todo.active = True  # Set the Job to Active.
            job_bot.running = True  # Set the Bot to Active too
            job_todo.job_start = datetime.now(timezone.utc)
            job_bot.last_seen = datetime.now(timezone.utc)
            job_todo.bot_id = job_bot.id  # Link Job and Bot.
            ret_msg = {
                "message": "ready",
                "job": job_todo.job,
                "job_uid": job_todo.uid,
                "nmap_nse": db.app.config.get("NMAP_NSE"),
                "nmap_ports": db.app.config.get("NMAP_PORTS"),
            }
        else:
            ret_msg = {"message": "ready", "job": ""}

        db.session.commit()

        return self.response(200, message=ret_msg)

    @expose("/sndjob", methods=["POST"])
    @safe
    def sndjobs(self):
        """
        Bot to Island connection to give back a job that was scanned

        Return a JobTodo.
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

        logger.debug("Agent UID %s send back a JOB", botinfo.get("UID"))

        # Tell the JOB that we finished
        job_bot = (
            db.session.query(Jobs)
            .filter(Jobs.uid == botinfo.get("JOB_UID"))
            .limit("1")
            .scalar()
        )
        job_bot.finished = True
        job_bot.active = False
        job_bot.job_end = datetime.now(timezone.utc)

        # Save the Job
        # Build path
        base = os.path.join(
            db.app.config.get("JSON_FOLDER"),
            botinfo.get("JOB_UID")[0],
            f"{botinfo.get("JOB_UID")}.json",
        )
        with open(base, "w", encoding="utf-8") as f:
            json.dump(json.loads(botinfo.get("RESULT")), f, indent=2)

        logger.debug("job_bot: %s", job_bot)
        # Check if we release the Target as Ready for a new Turn
        # Tell the JOB that we finished

        for target in job_bot.targets:
            logger.debug("target_id candidate to clean: %s", target.id)
            logger.debug("target_id candidate last scan %s", target.last_scan)
            previous_scan = target.last_scan
            # Alias for association table
            assoc = assoc_jobs_targets.alias()

            # requete SQLAlchemy
            count_query = (
                db.session.query(func.count(distinct(Jobs.id)))
                .select_from(assoc)
                .join(Jobs, assoc.c.job_id == Jobs.id, isouter=True)
                .filter(assoc.c.target_id == target.id, Jobs.finished == False)
            )

            logger.debug("%s", count_query)
            if count_query.scalar() == 0:
                # When we have done "All" jobs for a specific target.
                target.working = False  # The target is not working.
                target.last_previous_scan = previous_scan
                target.last_scan = datetime.now(timezone.utc)  # target last_scan
                db.session.merge(target)  # ensure attached
        db.session.commit()
        return self.response(200, message="ready")


appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(Api)
