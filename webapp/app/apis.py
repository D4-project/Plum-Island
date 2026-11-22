"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

# pylint: disable=too-many-lines

import base64
from datetime import date, datetime, time as datetime_time, timedelta, timezone
import hashlib
import ipaddress
import os
import json
import logging
import re
import time
import uuid
import meilisearch
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi
from flask_appbuilder.api import API_RESULT_RES_KEY, BaseApi, expose, safe, protect
from flask_appbuilder.filemanager import FileManager
from flask import request

from sqlalchemy import func, distinct, false, or_
from sqlalchemy.exc import IntegrityError, NoResultFound
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash
from marshmallow import Schema, fields, validate, validates, ValidationError
from .utils.scan_stats import claim_completed_job, increment_completed_counters
from .models import (
    Targets,
    Bots,
    ApiKeys,
    Jobs,
    Nses,
    Ports,
    Protos,
    ScanProfiles,
    TargetScanStates,
    assoc_jobs_targets,
)
from . import appbuilder, db
from .utils.mutils import is_valid_uuid, is_valid_ip, get_country, flat_marsh_error
from .utils.kvrocks import KVrocksIndexer
from .utils.index_generations import GenerationClient, CONTROL
from .utils.index_activity import prioritized_search
from .utils.result_parser import port_protocol_values
from .utils.tagrules import normalize_tags
from .utils.timeutils import utcnow_naive, ensure_utc_naive
from .utils.scan_cycles import reconcile_scanprofile_cycle
from .utils.network_enrichment import request_network_refresh
from .views import TargetsView


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
    PORTS_TARGETED = fields.Integer(
        required=False,
        strict=True,
        validate=validate.Range(min=0, max=10**12),
        metadata={
            "description": "Unique IP/transport/port pairs targeted by a completed attempt"
        },
    )
    JOB_UID = fields.String(
        required=False,
        metadata={"description": "Uid of the scan"},
    )
    ATTEMPT_UID = fields.String(
        required=False,
        metadata={"description": "Job-attempt identifier for stale-result protection"},
    )
    NSE_HASHES = fields.Dict(
        required=False,
        keys=fields.String(),
        values=fields.String(),
        metadata={"description": "Cached NSE SHA256 hashes keyed by NSE filename"},
    )
    capabilities = fields.List(
        fields.String(validate=validate.OneOf(("nmap", "masscan"))),
        validate=validate.Length(max=2),
        metadata={"description": "Tools reported by the agent at startup"},
    )
    masscan_ip = fields.String(allow_none=True)

    @validates("masscan_ip")
    def validate_masscan_source(self, value, **_kwargs):
        """Only a dedicated unicast address can enable banner jobs."""
        if value is None:
            return
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValidationError("Invalid Masscan source IP") from error
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
        ):
            raise ValidationError("Masscan source must be a unicast address")

    # Custom validator for the parameters
    @validates("UID")
    def validate_uid(self, value, **_kwargs):
        """
        UID Validation
        """
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid UID")

    @validates("JOB_UID")
    def validate_job_uid(self, value, **_kwargs):
        """
        JOB_UID Validation
        """
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid JOB_UID")

    @validates("ATTEMPT_UID")
    def validate_attempt_uid(self, value, **_kwargs):
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid ATTEMPT_UID")

    @validates("EXT_IP")
    def validate_ext_ip(self, value, **_kwargs):
        """
        IP Validation
        """
        if not is_valid_ip(value):  # Validate that IP is a public one.
            raise ValidationError("Invalid EXT_IP")

    @validates("AGENT_KEY")
    def validate_agent_key(self, value, **_kwargs):
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
            raise ValidationError("Invalid AGENT_KEY") from error
        raise ValidationError("Invalid AGENT_KEY")


class BotJobReleaseSchema(Schema):
    """
    Schema for interrupted job release requests.
    """

    UID = fields.String(required=True, metadata={"description": "Uniq Bot ID"})
    AGENT_KEY = fields.String(
        required=True,
        metadata={"description": "Bot Agent access Key"},
    )
    JOB_UID = fields.String(
        required=True,
        metadata={"description": "Uid of the scan job to release"},
    )
    ATTEMPT_UID = fields.String(
        required=False,
        metadata={"description": "Job-attempt identifier"},
    )
    ERROR = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "Optional interruption reason"},
    )

    @validates("UID")
    def validate_uid(self, value, **_kwargs):
        """
        UID Validation
        """
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid UID")

    @validates("JOB_UID")
    def validate_job_uid(self, value, **_kwargs):
        """
        JOB_UID Validation
        """
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid JOB_UID")

    @validates("ATTEMPT_UID")
    def validate_attempt_uid(self, value, **_kwargs):
        if len(value) != 36 or not is_valid_uuid(value):
            raise ValidationError("Invalid ATTEMPT_UID")

    @validates("AGENT_KEY")
    def validate_agent_key(self, value, **_kwargs):
        """
        Validate Authorization to interact with Island
        """
        if len(value) != 16 + 64:
            raise ValidationError("Invalid Agent Key")

        keyidx = value[0:16]
        try:
            agentkey = (
                db.session.query(ApiKeys).filter(ApiKeys.keyidx == keyidx).one().key
            )
            if check_password_hash(agentkey, value):
                return True
        except NoResultFound as error:
            raise ValidationError("Invalid AGENT_KEY") from error
        raise ValidationError("Invalid AGENT_KEY")


class BulkTargetsSchema(Schema):
    """
    Schema for Targets bulk import via API
    """

    bulk = fields.String(
        required=True,
        metadata={"description": "One IP/CIDR/FQDN per line."},
    )

    @validates("bulk")
    def validate_bulk(self, value, **_kwargs):
        """
        Ensure we have at least one target in the payload.
        """
        if not value or not value.strip():
            raise ValidationError("Bulk payload cannot be empty")
        return True


logger = logging.getLogger("flask_appbuilder")
PRIORITY_WEIGHTS = {
    4: 50,
    3: 20,
    2: 15,
    1: 10,
    0: 5,
}
MIN_JOB_RUNTIME_SECONDS = 1.0


def _nse_file_path(nse):
    """
    Resolve the uploaded NSE file path on disk.
    """
    return os.path.join(db.app.config.get("UPLOAD_FOLDER"), nse.filebody)


def _get_bot_by_uid(bot_uid):
    """
    Return the registered bot for an authenticated bot payload.
    """
    return (
        db.session.query(Bots)
        .filter(Bots.uid == bot_uid, Bots.active == True)
        .limit(1)
        .scalar()
    )


def _build_job_nmap_additional_params_payload(job):
    """Return optional profile parameters while tolerating legacy jobs."""
    return getattr(job, "nmap_additional_params", None)


def _build_job_nse_payload(scan_nses, agent_nse_hashes):
    """
    Build the job NSE payload and only include file contents when the agent cache
    does not already have the expected hash.
    """
    requested_names = [
        name.strip() for name in (scan_nses or "").split(",") if name.strip()
    ]
    if not requested_names:
        return [], []

    nse_by_name = {
        nse.name: nse
        for nse in db.session.query(Nses).filter(Nses.name.in_(requested_names)).all()
    }
    agent_nse_hashes = agent_nse_hashes or {}

    effective_names = []
    nse_payload = []
    for nse_name in requested_names:
        nse = nse_by_name.get(nse_name)
        if nse is None:
            logger.warning("Job references missing NSE script %s", nse_name)
            continue

        descriptor = {"name": nse.name, "hash": nse.hash}
        agent_hash = str(agent_nse_hashes.get(nse.name, "")).strip().lower()
        if agent_hash != nse.hash:
            with open(_nse_file_path(nse), "rb") as nse_file:
                descriptor["content_b64"] = base64.b64encode(nse_file.read()).decode(
                    "ascii"
                )

        effective_names.append(nse.name)
        nse_payload.append(descriptor)

    return effective_names, nse_payload


def _compatible_job_filter(bot):
    """Return the SQL predicate for jobs supported by this bot."""
    predicates = []
    if bot.has_nmap:
        predicates.append(or_(Jobs.scan_tool == "nmap", Jobs.scan_tool.is_(None)))
    if bot.has_masscan:
        masscan_filter = Jobs.scan_tool == "masscan"
        if not bot.masscan_ip:
            masscan_filter = masscan_filter & or_(
                Jobs.detect_protocol == False, Jobs.detect_protocol.is_(None)
            )
        predicates.append(masscan_filter)
    return or_(*predicates) if predicates else false()


def _claim_job_for_bot(job_id, bot, now, attempt_uid=None):
    """
    Atomically claim one queued job.

    Multiple agents can poll at the same time. The conditional UPDATE makes
    only one requester transition the job from queued to active.
    """
    return (
        db.session.query(Jobs)
        .filter(
            Jobs.id == job_id,
            Jobs.active == False,
            Jobs.finished == False,
            _compatible_job_filter(bot),
        )
        .update(
            {
                Jobs.active: True,
                Jobs.job_start: now,
                Jobs.bot_id: bot.id,
                Jobs.attempt_uid: attempt_uid,
            },
            synchronize_session=False,
        )
    )


def _release_interrupted_job(job, bot, now):
    """
    Release an interrupted job assigned to a bot.

    Mutates only jobs assigned to the requesting bot. Finished jobs and already
    released queued jobs are treated as idempotent success.
    """
    if job.finished:
        if job.bot_id == bot.id:
            bot.running = False
            bot.last_seen = now
        return True, "already finished"

    if job.bot_id is None:
        if job.active:
            return False, "forbidden"
        return True, "already released"

    if job.bot_id != bot.id:
        return False, "forbidden"

    if not job.active:
        job.bot_id = None
        job.job_start = None
        job.attempt_uid = None
        bot.running = False
        bot.last_seen = now
        return True, "already released"

    job.active = False
    job.bot_id = None
    job.job_start = None
    job.attempt_uid = None
    bot.running = False
    bot.last_seen = now
    return True, "released"


def _get_available_job_priorities(bot):
    """
    Return the priority queues that currently have at least one waiting job.
    """
    rows = (
        db.session.query(Jobs.priority)
        .filter(
            Jobs.active == False, Jobs.finished == False, _compatible_job_filter(bot)
        )
        .distinct()
        .all()
    )
    priorities = set()
    for row in rows:
        try:
            priority = int(row[0])
        except (TypeError, ValueError):
            continue
        if priority in PRIORITY_WEIGHTS:
            priorities.add(priority)
    return priorities


def _select_weighted_priority(available_priorities):
    """
    Smooth weighted round-robin over currently non-empty priority queues.
    """
    available_priorities = set(available_priorities or [])
    if not available_priorities:
        return []

    state = db.app.config.setdefault(
        "priority_weighted_round_robin",
        {priority: 0 for priority in PRIORITY_WEIGHTS},
    )
    for priority in PRIORITY_WEIGHTS:
        state.setdefault(priority, 0)
        if priority not in available_priorities:
            state[priority] = 0

    total_weight = 0
    for priority in sorted(available_priorities, reverse=True):
        weight = PRIORITY_WEIGHTS[priority]
        state[priority] += weight
        total_weight += weight

    selected_priority = max(
        available_priorities,
        key=lambda priority: (state[priority], priority),
    )
    state[selected_priority] -= total_weight
    db.app.config["priority_weighted_round_robin"] = state

    fallback_priorities = sorted(
        available_priorities - {selected_priority},
        reverse=True,
    )
    return [selected_priority] + fallback_priorities


class PublicTargetsApi(ModelRestApi):
    """
    This class implement the API access for the Target definition
    """

    datamodel = SQLAInterface(Targets)
    # Server-managed timestamps, AS associations and lease fields are read-only.
    add_columns = ["value", "description", "active", "priority", "scanprofiles"]
    edit_columns = ["value", "description", "active", "priority", "scanprofiles"]
    list_columns = [
        "id",
        "value",
        "description",
        "active",
        "priority",
        "working",
        "last_scan",
        "last_previous_scan",
        "scan_unit_count",
        "scanprofiles",
        "created_at",
        "is_ip_cidr",
        "network_updated_at",
    ]
    show_columns = list_columns

    @staticmethod
    def _insertion_metadata(item):
        """Report server-owned metadata without accepting it in input schemas."""
        return {
            "created_at": item.created_at.isoformat() + "Z",
            "target_type": item.target_type,
            "is_ip_cidr": item.is_ip_cidr,
            "network_refresh_pending": bool(item.network_refresh_pending),
        }

    def _coverage_error(self, item):
        return TargetsView._target_coverage_error(item)

    def post_headless(self):
        """
        POST/Add target with CIDR coverage validation before insert.
        """
        if not request.is_json:
            return self.response_400(message="Request is not JSON")
        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as err:
            return self.response_422(message=err.messages)

        coverage_error = self._coverage_error(item)
        if coverage_error:
            return self.response_422(message=coverage_error)

        self.pre_add(item)
        try:
            self.datamodel.add(item, raise_exception=True)
            self.post_add(item)
            return self.response(
                201,
                **{
                    API_RESULT_RES_KEY: {
                        **self.add_model_schema.dump(item, many=False),
                        **self._insertion_metadata(item),
                    },
                    "id": self.datamodel.get_pk_value(item),
                },
            )
        except IntegrityError as error:
            return self.response_422(message=str(error.orig))

    def put_headless(self, pk):
        """
        PUT/Edit target with CIDR coverage validation before update.
        """
        item = self.datamodel.get(pk, self._base_filters)
        if not request.is_json:
            return self.response_400(message="Request is not JSON")
        if not item:
            return self.response_404()
        try:
            data = self._merge_update_item(item, request.json)
            item = self.edit_model_schema.load(data, instance=item)
        except ValidationError as err:
            return self.response_422(message=err.messages)

        coverage_error = self._coverage_error(item)
        if coverage_error:
            return self.response_422(message=coverage_error)

        self.pre_update(item)
        try:
            self.datamodel.edit(item, raise_exception=True)
            self.post_update(item)
            return self.response(
                200,
                **{API_RESULT_RES_KEY: self.edit_model_schema.dump(item, many=False)},
            )
        except IntegrityError as error:
            return self.response_422(message=str(error.orig))


class TargetsApi(BaseApi):
    """
    Additional API endpoints for managing targets (Swagger exposed).
    """

    route_base = "/targets_api"
    openapi_spec_tag = "Targets API"
    bulk_schema = BulkTargetsSchema()

    @expose("/bulk_import", methods=["POST"])
    @protect()
    @safe
    def bulk_import(self):
        """
        summary: Bulk import targets (IP, CIDR, FQDN).
        description: |
            Accepts the same newline-separated payload as the HTML form and
            queues each entry for scanning.
        parameters:
            - in: body
              name: payload
              required: true
              schema:
                  type: object
                  properties:
                      bulk:
                          type: string
                          description: One IP/CIDR/FQDN per line.
                  required:
                      - bulk
        responses:
            200:
                description: Import log and statistics.
                content:
                    application/json:
                        schema:
                            type: object
        """

        try:
            payload = request.get_json(force=True)
        except Exception:
            return self.response_400(message="Invalid or missing JSON payload")

        if not isinstance(payload, dict):
            payload = {"bulk": payload}

        try:
            data = self.bulk_schema.load(payload)
        except ValidationError as err:
            return self.response_400(
                message=f"Invalid input: {flat_marsh_error(err.messages)}"
            )

        bulk_text = data["bulk"].replace("\r\n", "\r").replace("\n", "\r")
        submitted_entries = [
            entry.strip() for entry in bulk_text.split("\r") if entry.strip()
        ]
        log = TargetsView.do_bulk_import(bulk_text)
        full_log = f"{log}\nEnd of import"
        log_lines = [line for line in full_log.split("\n") if line.strip()]

        return self.response(
            200,
            message={"log": log_lines, "entries_submitted": len(submitted_entries)},
        )


class Api(BaseApi):
    """
    This class implements all interactions with the BOTS.
    """

    route_base = "/bot_api"
    openapi_spec_tag = "Bots API"

    @expose("/protocol", methods=["GET"])
    @safe
    def protocol(self):
        """Advertise support for scanner inventories without changing bot state."""
        return self.response(200, tool_inventory=True)

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

        tools = botinfo.get("capabilities", ["nmap"])
        capabilities_reported = "capabilities" in botinfo
        new_bot = Bots(
            # Last Seen is autoupdated at creation
            uid=botinfo.get("UID"),
            ip=botinfo.get("EXT_IP"),
            country=get_country(botinfo.get("EXT_IP")),
            device_model=botinfo.get("DEVICE_MODEL"),
            agent_version=botinfo.get("AGENT_VERSION"),
            system_version=botinfo.get("SYSTEM_VERSION"),
            has_nmap="nmap" in tools,
            has_masscan="masscan" in tools,
            masscan_ip=botinfo.get("masscan_ip") if "masscan" in tools else None,
            supports_job_attempts=capabilities_reported,
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
                    Bots.last_seen: utcnow_naive(),
                    Bots.ip: botinfo.get("EXT_IP"),
                    Bots.device_model: botinfo.get("DEVICE_MODEL"),
                    Bots.agent_version: botinfo.get("AGENT_VERSION"),
                    Bots.system_version: botinfo.get("SYSTEM_VERSION"),
                    Bots.has_nmap: "nmap" in tools,
                    Bots.has_masscan: "masscan" in tools,
                    Bots.masscan_ip: (
                        botinfo.get("masscan_ip") if "masscan" in tools else None
                    ),
                    Bots.supports_job_attempts: capabilities_reported,
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
        job_bot = _get_bot_by_uid(botinfo.get("UID"))
        if job_bot is None:
            logger.warning(
                "Unknown or inactive bot %s requested a job", botinfo.get("UID")
            )
            return self.response(403, message="forbidden")

        # Get one job to do using smooth weighted round-robin over non-empty
        # priority queues. Priority 4 gets the largest share when present, but
        # lower queues inherit capacity when higher queues are empty.
        prio_list = []
        if job_bot.has_nmap or job_bot.has_masscan:
            prio_list = _select_weighted_priority(
                _get_available_job_priorities(job_bot)
            )
        job_todo = None
        for prio in prio_list:
            candidate = (
                db.session.query(Jobs)
                .filter(
                    Jobs.active == False,
                    Jobs.finished == False,
                    Jobs.priority == prio,
                    _compatible_job_filter(job_bot),
                )
                .order_by(Jobs.job_creation.asc())  # oldest first
                .first()
            )
            if not candidate:
                continue

            now = utcnow_naive()
            attempt_uid = str(uuid.uuid4()) if job_bot.supports_job_attempts else None
            if _claim_job_for_bot(candidate.id, job_bot, now, attempt_uid) != 1:
                db.session.rollback()
                continue

            job_todo = candidate
            job_todo.active = True
            job_todo.job_start = now
            job_todo.bot_id = job_bot.id
            job_todo.attempt_uid = attempt_uid
            job_bot.running = True  # Set the Bot to Active too
            job_bot.last_seen = now
            db.session.add(job_bot)
            db.session.add(job_todo)
            if job_todo:
                break  # A soon as a Job is found... return.

        # Now whe have maybe a job to launch.
        if job_todo:
            scan_tool = getattr(job_todo, "scan_tool", None) or "nmap"
            ret_msg = {
                "message": "ready",
                "job": job_todo.job,
                "job_uid": job_todo.uid,
                "scan_tool": scan_tool,
                "report_target_count": True,
                "attempt_uid": job_todo.attempt_uid,
                "scan_ports": (
                    job_todo.scan_ports.split(",") if job_todo.scan_ports else []
                ),
            }
            if scan_tool == "masscan":
                ret_msg["detect_protocol"] = bool(job_todo.detect_protocol)
            else:
                try:
                    nmap_nse, nse_scripts = _build_job_nse_payload(
                        job_todo.scan_nses,
                        botinfo.get("NSE_HASHES"),
                    )
                except OSError as error:
                    db.session.rollback()
                    logger.exception(
                        "Unable to prepare NSE payloads for job %s", job_todo.uid
                    )
                    return self.response_400(
                        message=f"Unable to prepare NSE payloads: {error}"
                    )
                ret_msg.update(
                    {
                        "nmap_nse": nmap_nse,
                        "nse_scripts": nse_scripts,
                        "nmap_ports": ret_msg["scan_ports"],
                        "nmap_additional_params": _build_job_nmap_additional_params_payload(
                            job_todo
                        ),
                    }
                )
        else:
            job_bot.last_seen = utcnow_naive()
            ret_msg = {"message": "ready", "job": ""}

        db.session.commit()

        return self.response(200, message=ret_msg)

    @expose("/releasejob", methods=["POST"])
    @safe
    def releasejobs(self):
        """
        Bot to Island connection to release an interrupted job.
        """
        try:
            data = request.get_json(force=True)
            if not isinstance(data, dict):
                data = json.loads(data)

            botinfoschema = BotJobReleaseSchema()
            botinfo = botinfoschema.load(data)

        except ValidationError as err:
            return self.response_400(
                message=f"Invalid input: {flat_marsh_error(err.messages)}"
            )

        logger.debug(
            "Agent UID %s releasing interrupted job %s",
            botinfo.get("UID"),
            botinfo.get("JOB_UID"),
        )

        releasing_bot = _get_bot_by_uid(botinfo.get("UID"))
        if releasing_bot is None:
            logger.warning(
                "Unknown or inactive bot %s tried to release job %s",
                botinfo.get("UID"),
                botinfo.get("JOB_UID"),
            )
            return self.response(403, message="forbidden")

        job_bot = (
            db.session.query(Jobs)
            .filter(Jobs.uid == botinfo.get("JOB_UID"))
            .limit(1)
            .scalar()
        )
        if job_bot is None:
            logger.warning(
                "Bot %s tried to release unknown job %s",
                botinfo.get("UID"),
                botinfo.get("JOB_UID"),
            )
            return self.response(404, message="job not found")

        if job_bot.attempt_uid and botinfo.get("ATTEMPT_UID") != job_bot.attempt_uid:
            logger.warning(
                "Bot %s tried to release stale attempt for job %s",
                botinfo.get("UID"),
                job_bot.uid,
            )
            return self.response(409, message="stale job attempt")

        released, state = _release_interrupted_job(
            job_bot,
            releasing_bot,
            utcnow_naive(),
        )
        if not released:
            logger.warning(
                "Bot %s tried to release job %s assigned to bot_id %s",
                botinfo.get("UID"),
                job_bot.uid,
                job_bot.bot_id,
            )
            return self.response(403, message="forbidden")

        logger.info(
            "Bot %s releasejob %s: %s%s",
            botinfo.get("UID"),
            job_bot.uid,
            state,
            f" ({botinfo.get('ERROR')})" if botinfo.get("ERROR") else "",
        )
        db.session.commit()
        return self.response(200, message="ready")

    @expose("/sndjob", methods=["POST"])
    @safe
    def sndjobs(self):
        """
        Bot to Island connection to give back a job that was scanned

        Return a JobTodo.
        """
        request_started = time.perf_counter()
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

        submitting_bot = _get_bot_by_uid(botinfo.get("UID"))
        if submitting_bot is None:
            logger.warning(
                "Unknown or inactive bot %s submitted job %s",
                botinfo.get("UID"),
                botinfo.get("JOB_UID"),
            )
            return self.response(403, message="forbidden")

        # Tell the JOB that we finished
        lookup_started = time.perf_counter()
        job_bot = (
            db.session.query(Jobs)
            .filter(Jobs.uid == botinfo.get("JOB_UID"))
            .limit(1)
            .scalar()
        )
        logger.debug(
            "sndjob debug: loaded job %s in %.2fs",
            botinfo.get("JOB_UID"),
            time.perf_counter() - lookup_started,
        )
        if job_bot is None:
            logger.warning(
                "Bot %s submitted unknown job %s",
                botinfo.get("UID"),
                botinfo.get("JOB_UID"),
            )
            return self.response(404, message="job not found")

        if job_bot.finished and not job_bot.active:
            logger.info(
                "Bot %s resubmitted already completed job %s assigned to bot_id %s; returning idempotent success",
                botinfo.get("UID"),
                job_bot.uid,
                job_bot.bot_id,
            )
            submitting_bot.running = False
            submitting_bot.last_seen = utcnow_naive()
            db.session.commit()
            return self.response(200, message="ready")

        if job_bot.bot_id != submitting_bot.id:
            logger.warning(
                "Bot %s submitted stale or late result for job %s assigned to bot_id %s",
                botinfo.get("UID"),
                job_bot.uid,
                job_bot.bot_id,
            )
            return self.response(403, message="forbidden")

        if job_bot.attempt_uid and botinfo.get("ATTEMPT_UID") != job_bot.attempt_uid:
            logger.warning(
                "Bot %s submitted stale attempt for job %s",
                botinfo.get("UID"),
                job_bot.uid,
            )
            return self.response(409, message="stale job attempt")

        if not job_bot.active or job_bot.finished:
            logger.warning(
                "Bot %s submitted job %s in invalid state active=%s finished=%s",
                botinfo.get("UID"),
                job_bot.uid,
                job_bot.active,
                job_bot.finished,
            )
            return self.response(409, message="job is not active")

        job_start = ensure_utc_naive(job_bot.job_start)
        now = utcnow_naive()
        if job_start is None:
            logger.warning(
                "Bot %s submitted job %s without start time",
                botinfo.get("UID"),
                job_bot.uid,
            )
            return self.response(409, message="job is not active")

        elapsed_seconds = (now - job_start).total_seconds()
        # Masscan can legitimately finish a small or empty job in under one
        # second. Keep the historical guard for Nmap jobs only.
        if job_bot.scan_tool != "masscan" and elapsed_seconds < MIN_JOB_RUNTIME_SECONDS:
            logger.warning(
                "Bot %s submitted job %s too quickly after %.3fs",
                botinfo.get("UID"),
                job_bot.uid,
                elapsed_seconds,
            )
            return self.response(429, message="job submitted too quickly")

        # Write the result file BEFORE mutating ORM state.
        # If the write fails (disk full, OSError, malformed JSON), the job
        # must not be marked finished — the agent can retry and resubmit.
        result_payload = botinfo.get("RESULT")
        if result_payload is None:
            logger.warning(
                "Bot %s submitted job %s without RESULT payload",
                botinfo.get("UID"),
                botinfo.get("JOB_UID"),
            )
            db.session.rollback()
            return self.response(400, message="missing result")

        base = os.path.join(
            db.app.config.get("JSON_FOLDER"),
            botinfo.get("JOB_UID")[0],
            f"{botinfo.get('JOB_UID')}.json",
        )
        try:
            result_data = json.loads(result_payload)
            with open(base, "w", encoding="utf-8") as f:
                json.dump(result_data, f, indent=2)
        except (OSError, TypeError, json.JSONDecodeError):
            logger.exception(
                "Failed to write result file for job %s", botinfo.get("JOB_UID")
            )
            db.session.rollback()
            return self.response(500, message="result storage failed")

        if not claim_completed_job(db.session, job_bot, now):
            db.session.rollback()
            completed = (
                db.session.query(Jobs.finished).filter(Jobs.id == job_bot.id).scalar()
            )
            if completed:
                return self.response(200, message="ready")
            return self.response(409, message="job is no longer active")

        job_bot.finished = True
        job_bot.active = False
        job_bot.job_end = now
        submitting_bot.running = False
        submitting_bot.last_seen = now

        logger.debug("job_bot: %s", job_bot)
        # Check if we release the Target as Ready for a new Turn
        # Tell the JOB that we finished

        sync_started = time.perf_counter()
        with db.session.no_autoflush:
            logger.debug(
                "sndjob debug: syncing %s targets for job %s",
                len(job_bot.targets),
                job_bot.uid,
            )
            for target in job_bot.targets:
                request_network_refresh(target)
                logger.debug("target_id candidate to clean: %s", target.id)
                logger.debug("target_id candidate last scan %s", target.last_scan)
                previous_scan = ensure_utc_naive(target.last_scan)
                # Alias for association table
                assoc = assoc_jobs_targets.alias()

                # requete SQLAlchemy
                count_query = (
                    db.session.query(func.count(distinct(Jobs.id)))
                    .select_from(assoc)
                    .join(Jobs, assoc.c.job_id == Jobs.id, isouter=True)
                    .filter(
                        assoc.c.target_id == target.id,
                        Jobs.id != job_bot.id,
                        Jobs.finished == False,
                        Jobs.scanprofile_id == job_bot.scanprofile_id,
                    )
                )

                scan_state = (
                    db.session.query(TargetScanStates)
                    .filter(
                        TargetScanStates.target_id == target.id,
                        TargetScanStates.scanprofile_id == job_bot.scanprofile_id,
                    )
                    .one_or_none()
                )

                if count_query.scalar() == 0:
                    completion_time = utcnow_naive()
                    if scan_state is not None:
                        scan_state.working = False
                        scan_state.last_previous_scan = ensure_utc_naive(
                            scan_state.last_scan
                        )
                        scan_state.last_scan = completion_time
                    target.last_previous_scan = previous_scan
                    target.last_scan = completion_time

                target.working = any(state.working for state in target.scan_states)
                db.session.merge(target)  # ensure attached
        logger.debug(
            "sndjob debug: target sync for job %s completed in %.2fs",
            job_bot.uid,
            time.perf_counter() - sync_started,
        )
        if job_bot.scanprofile_id is not None:
            # Historical-cycle pruning may unlink many retained jobs. It is
            # unrelated to accepting this result and must not extend this
            # latency-sensitive SQLite writer transaction.
            reconcile_scanprofile_cycle(
                job_bot.scanprofile_id,
                prune_history=False,
            )
        # Lock the shared minute bucket only after target/profile synchronization.
        increment_completed_counters(
            db.session, job_bot, result_data, now, botinfo.get("PORTS_TARGETED")
        )
        commit_started = time.perf_counter()
        db.session.commit()
        logger.debug(
            "sndjob debug: commit for job %s completed in %.2fs (total_request=%.2fs)",
            job_bot.uid,
            time.perf_counter() - commit_started,
            time.perf_counter() - request_started,
        )
        scan_results_received = (
            len(result_data)
            if isinstance(result_data, list)
            else int(isinstance(result_data, dict))
        )
        logger.info(
            "Scanner result received: job=%s json_files=1 scan_results=%s",
            job_bot.uid,
            scan_results_received,
        )
        return self.response(200, message="ready")


class ScanProfilesApi(BaseApi):
    """
    REST API for managing scan profiles.

    Provides programmatic equivalents of the /scanprofilesview HTML form: list,
    create, read, update, and delete scan profile entries. All requests and
    responses are JSON.
    """

    route_base = "/api/v1/scanprofiles"
    openapi_spec_tag = "Scan Profiles API"
    _allowed_fields = {
        "name",
        "scan_tool",
        "detect_protocol",
        "port_ids",
        "nse_ids",
        "scan_cycle_minutes",
        "priority",
        "apply_to_all",
    }

    @staticmethod
    def _summary(profile):
        return {
            "id": profile.id,
            "name": profile.name,
            "scan_tool": profile.scan_tool,
            "detect_protocol": profile.detect_protocol,
            "scan_cycle_minutes": profile.scan_cycle_minutes,
            "priority": profile.priority,
            "apply_to_all": profile.apply_to_all,
        }

    @classmethod
    def _serialize(cls, profile):
        return {
            **cls._summary(profile),
            "port_ids": sorted(port.id for port in profile.ports),
            "nse_ids": sorted(nse.id for nse in profile.nses),
        }

    @staticmethod
    def _require_json_object(data):
        if not isinstance(data, dict):
            raise ValueError("JSON body required")

    @classmethod
    def _reject_unknown_fields(cls, data):
        unknown = sorted(set(data) - cls._allowed_fields)
        if unknown:
            raise ValueError(f"Unknown fields: {unknown}")

    @classmethod
    def _require_update_fields(cls, data):
        if not any(field in data for field in cls._allowed_fields):
            raise ValueError("JSON body with at least one supported field required")

    @staticmethod
    def _normalize_profile_name(value, message):
        if not isinstance(value, str):
            raise ValueError(message)

        name = value.strip()
        if not name:
            raise ValueError(message)

        return name

    @staticmethod
    def _normalize_positive_integer(value, field_name):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"'{field_name}' must be a positive integer")

        return value

    @staticmethod
    def _normalize_priority(value):
        if isinstance(value, bool) or value not in (0, 1, 2, 3, 4):
            raise ValueError("'priority' must be 0, 1, 2, 3, or 4")

        return value

    @staticmethod
    def _normalize_boolean(value, field_name):
        if not isinstance(value, bool):
            raise ValueError(f"'{field_name}' must be a boolean")

        return value

    @staticmethod
    def _normalize_id_list(value, field_name, allow_empty=True):
        if value is None:
            value = []

        if not isinstance(value, list):
            raise ValueError(f"'{field_name}' must be a list of integer IDs")

        seen = set()
        item_ids = []
        for item_id in value:
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
                raise ValueError(
                    f"'{field_name}' must be a list of positive integer IDs"
                )
            if item_id not in seen:
                seen.add(item_id)
                item_ids.append(item_id)

        if not allow_empty and not item_ids:
            raise ValueError("'port_ids' must contain at least one port ID")

        return item_ids

    @staticmethod
    def _get_related_records(model, item_ids, label):
        if not item_ids:
            return []

        records = db.session.query(model).filter(model.id.in_(item_ids)).all()
        records_by_id = {record.id: record for record in records}
        missing = [item_id for item_id in item_ids if item_id not in records_by_id]
        if missing:
            raise ValueError(f"Unknown {label} IDs: {missing}")

        return [records_by_id[item_id] for item_id in item_ids]

    @staticmethod
    def _profile_exists(name, current_id=None):
        query = db.session.query(ScanProfiles).filter(ScanProfiles.name == name)
        if current_id is not None:
            query = query.filter(ScanProfiles.id != current_id)
        return query.first() is not None

    @staticmethod
    def _validate_scan_tool(value):
        if value not in ("nmap", "masscan"):
            raise ValueError("'scan_tool' must be 'nmap' or 'masscan'")
        return value

    def _validated_create_payload(self, data):
        self._require_json_object(data)
        self._reject_unknown_fields(data)

        if "name" not in data:
            raise ValueError("'name' is required")

        name = self._normalize_profile_name(data["name"], "'name' is required")
        if self._profile_exists(name):
            raise ValueError(f"Profile '{name}' already exists")

        port_ids = self._normalize_id_list(
            data.get("port_ids", []),
            "port_ids",
            allow_empty=False,
        )
        nse_ids = self._normalize_id_list(data.get("nse_ids", []), "nse_ids")

        return {
            "name": name,
            "scan_tool": self._validate_scan_tool(data.get("scan_tool", "nmap")),
            "detect_protocol": self._normalize_boolean(
                data.get("detect_protocol", False), "detect_protocol"
            ),
            "scan_cycle_minutes": self._normalize_positive_integer(
                data.get("scan_cycle_minutes", 720),
                "scan_cycle_minutes",
            ),
            "priority": self._normalize_priority(data.get("priority", 0)),
            "apply_to_all": self._normalize_boolean(
                data.get("apply_to_all", False),
                "apply_to_all",
            ),
            "ports": self._get_related_records(Ports, port_ids, "port"),
            "nses": self._get_related_records(Nses, nse_ids, "NSE"),
        }

    def _validated_update_payload(self, data, pk):
        self._require_json_object(data)
        self._reject_unknown_fields(data)
        self._require_update_fields(data)

        payload = {}
        if "scan_tool" in data:
            payload["scan_tool"] = self._validate_scan_tool(data["scan_tool"])
        if "detect_protocol" in data:
            payload["detect_protocol"] = self._normalize_boolean(
                data["detect_protocol"], "detect_protocol"
            )
        if "name" in data:
            name = self._normalize_profile_name(data["name"], "'name' cannot be empty")
            if self._profile_exists(name, current_id=pk):
                raise ValueError(f"Profile '{name}' already exists")
            payload["name"] = name

        if "scan_cycle_minutes" in data:
            payload["scan_cycle_minutes"] = self._normalize_positive_integer(
                data["scan_cycle_minutes"],
                "scan_cycle_minutes",
            )

        if "priority" in data:
            payload["priority"] = self._normalize_priority(data["priority"])

        if "apply_to_all" in data:
            payload["apply_to_all"] = self._normalize_boolean(
                data["apply_to_all"],
                "apply_to_all",
            )

        if "port_ids" in data:
            port_ids = self._normalize_id_list(
                data["port_ids"],
                "port_ids",
                allow_empty=False,
            )
            payload["ports"] = self._get_related_records(Ports, port_ids, "port")

        if "nse_ids" in data:
            nse_ids = self._normalize_id_list(data["nse_ids"], "nse_ids")
            payload["nses"] = self._get_related_records(Nses, nse_ids, "NSE")

        return payload

    @expose("/", methods=["GET"])
    @protect()
    @safe
    def list(self):
        """
        ---
        get:
          summary: List scan profile summaries sorted by name and ID.
          parameters:
            - {in: query, name: page, schema: {type: integer, minimum: 1, default: 1}}
            - {in: query, name: page_size, schema: {type: integer, minimum: 1, maximum: 100, default: 50}}
          responses:
            "200":
              description: Array of scan profile objects sorted by name.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: array
                        items:
                          type: object
                          properties:
                            id:
                              type: integer
                            name:
                              type: string
                            scan_tool:
                              type: string
                              enum: [nmap, masscan]
                            detect_protocol:
                              type: boolean
                            scan_cycle_minutes:
                              type: integer
                            priority:
                              type: integer
                            apply_to_all:
                              type: boolean
                      total:
                        type: integer
        """
        try:
            page = int(request.args.get("page", 1))
            size = int(request.args.get("page_size", 50))
        except ValueError:
            return self.response_400(message="Pagination requires integer values")
        if not 1 <= page <= 2147483647 or not 1 <= size <= 100:
            return self.response_400(message="Invalid page or page_size")
        query = db.session.query(ScanProfiles)
        profiles = (
            query.order_by(ScanProfiles.name, ScanProfiles.id)
            .offset((page - 1) * size)
            .limit(size)
            .all()
        )
        return self.response(
            200, total=query.count(), result=[self._summary(item) for item in profiles]
        )

    @expose("/", methods=["POST"])
    @protect()
    @safe
    def create(self):
        """
        ---
        post:
          summary: Create a new scan profile.
          description: |
            Accepts a JSON body with ``name`` and at least one port ID in
            ``port_ids``. Optional fields are ``nse_ids``,
            ``scan_cycle_minutes`` (default 720), ``priority`` (0-4, default 0),
            ``apply_to_all`` (default false), ``scan_tool`` (default nmap), and
            ``detect_protocol`` (default false).
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - name
                    - port_ids
                  properties:
                    name:
                      type: string
                    scan_tool:
                      type: string
                      enum: [nmap, masscan]
                    detect_protocol:
                      type: boolean
                    port_ids:
                      type: array
                      minItems: 1
                      items:
                        type: integer
                    nse_ids:
                      type: array
                      items:
                        type: integer
                    scan_cycle_minutes:
                      type: integer
                      minimum: 1
                    priority:
                      type: integer
                      enum: [0, 1, 2, 3, 4]
                    apply_to_all:
                      type: boolean
          responses:
            "201":
              description: Scan profile created successfully.
            "413":
              description: Request exceeds the configured body size limit.
            "400":
              description: Missing/invalid fields or duplicate name.
        """
        try:
            data = request.get_json(silent=True)
            payload = self._validated_create_payload(data)
            ScanProfiles.validate_banner_support(
                db.session, payload["scan_tool"], payload["detect_protocol"]
            )
        except RequestEntityTooLarge:
            return self.response(413, message="Request exceeds configured size limit")
        except ValueError as error:
            return self.response_400(message=str(error))

        item = ScanProfiles(**payload)
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message=f"Profile '{payload['name']}' already exists"
            )

        return self.response(201, result=self._serialize(item))

    @expose("/<int:pk>", methods=["GET"])
    @protect()
    @safe
    def get(self, pk):
        """
        ---
        get:
          summary: Get a single scan profile by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the scan profile to retrieve.
          responses:
            "200":
              description: Scan profile object.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
                        properties:
                          id:
                            type: integer
                          name:
                            type: string
                          scan_tool:
                            type: string
                            enum: [nmap, masscan]
                          detect_protocol:
                            type: boolean
                          scan_cycle_minutes:
                            type: integer
                          priority:
                            type: integer
                          apply_to_all:
                            type: boolean
                          port_ids:
                            type: array
                            items:
                              type: integer
                          nse_ids:
                            type: array
                            items:
                              type: integer
            "404":
              description: Scan profile not found.
        """
        item = (
            db.session.query(ScanProfiles).filter(ScanProfiles.id == pk).one_or_none()
        )
        if item is None:
            return self.response_404()
        return self.response(200, result=self._serialize(item))

    @expose("/<int:pk>", methods=["PUT"])
    @protect()
    @safe
    def update(self, pk):
        """
        ---
        put:
          summary: Update a scan profile by ID.
          description: |
            Accepts a JSON body with any subset of ``name``, ``port_ids``,
            ``nse_ids``, ``scan_cycle_minutes``, ``priority``, ``apply_to_all``,
            ``scan_tool``, and ``detect_protocol``.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the scan profile to update.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    name:
                      type: string
                    scan_tool:
                      type: string
                      enum: [nmap, masscan]
                    detect_protocol:
                      type: boolean
                    port_ids:
                      type: array
                      minItems: 1
                      items:
                        type: integer
                    nse_ids:
                      type: array
                      items:
                        type: integer
                    scan_cycle_minutes:
                      type: integer
                      minimum: 1
                    priority:
                      type: integer
                      enum: [0, 1, 2, 3, 4]
                    apply_to_all:
                      type: boolean
          responses:
            "200":
              description: Updated scan profile object.
            "413":
              description: Request exceeds the configured body size limit.
            "400":
              description: Invalid fields or name collision.
            "404":
              description: Scan profile not found.
        """
        item = (
            db.session.query(ScanProfiles).filter(ScanProfiles.id == pk).one_or_none()
        )
        if item is None:
            return self.response_404()

        try:
            data = request.get_json(silent=True)
            payload = self._validated_update_payload(data, pk)
            ScanProfiles.validate_banner_support(
                db.session,
                payload.get("scan_tool", item.scan_tool),
                payload.get("detect_protocol", item.detect_protocol),
            )
        except RequestEntityTooLarge:
            return self.response(413, message="Request exceeds configured size limit")
        except ValueError as error:
            return self.response_400(message=str(error))

        for field_name, value in payload.items():
            setattr(item, field_name, value)
        item.priority_retag_pending = True

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message="Scan profile update violates a unique constraint"
            )

        return self.response(200, result=self._serialize(item))

    @expose("/<int:pk>", methods=["DELETE"])
    @protect()
    @safe
    def delete(self, pk):
        """
        ---
        delete:
          summary: Delete a scan profile by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the scan profile to delete.
          responses:
            "200":
              description: Scan profile deleted.
            "400":
              description: Scan profile could not be deleted.
            "404":
              description: Scan profile not found.
        """
        item = (
            db.session.query(ScanProfiles).filter(ScanProfiles.id == pk).one_or_none()
        )
        if item is None:
            return self.response_404()

        name = item.name
        db.session.delete(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message=f"Scan profile '{name}' could not be deleted"
            )

        return self.response(200, message=f"Scan profile '{name}' deleted")


class NsesApi(BaseApi):
    """
    REST API for managing NSE (Nmap Script Engine) scripts.

    Provides programmatic equivalents of the /nsesview HTML form. File upload
    uses multipart/form-data; all other responses are JSON.
    """

    route_base = "/api/v1/nses"
    openapi_spec_tag = "NSE Scripts API"

    @staticmethod
    def _serialize_nse(item):
        return {"id": item.id, "name": item.name, "hash": item.hash}

    @staticmethod
    def _normalize_nse_name(value, append_suffix=False):
        raw_name = (value or "").strip()
        if not raw_name:
            raise ValueError("NSE script name cannot be empty")

        name = os.path.basename(raw_name)
        if not name or name in {".", ".."}:
            raise ValueError("NSE script name cannot be empty")

        if append_suffix and not name.lower().endswith(".nse"):
            name = f"{name}.nse"

        if name.lower() == ".nse":
            raise ValueError("NSE script name cannot be empty")

        if not name.lower().endswith(".nse"):
            raise ValueError("Only .nse files are allowed")

        return name

    @classmethod
    def _upload_metadata(cls, upload):
        if upload is None or not getattr(upload, "filename", ""):
            raise ValueError("Field 'filebody' with a .nse file is required")

        filename = cls._normalize_nse_name(upload.filename)
        file_bytes = upload.read()
        upload.stream.seek(0)
        return filename, hashlib.sha256(file_bytes).hexdigest()

    @staticmethod
    def _delete_uploaded_file(file_manager, file_name):
        if not file_name:
            return
        try:
            file_manager.delete_file(file_name)
        except OSError:
            logger.exception("Failed to delete NSE upload file %s", file_name)

    @staticmethod
    def _save_uploaded_file(file_manager, item, upload):
        stored_name = file_manager.generate_name(item, upload)
        return file_manager.save_file(upload, stored_name)

    @staticmethod
    def _duplicate_value_response():
        return BaseApi.response(
            400,
            message="An NSE script with this name or SHA256 already exists",
        )

    @expose("/", methods=["GET"])
    @protect()
    @safe
    def list(self):
        """
        ---
        get:
          summary: List all NSE scripts.
          responses:
            "200":
              description: Array of NSE script metadata objects.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: array
                        items:
                          type: object
                          properties:
                            id:
                              type: integer
                            name:
                              type: string
                            hash:
                              type: string
        """
        nses = db.session.query(Nses).order_by(Nses.name.asc()).all()
        return self.response(
            200,
            result=[self._serialize_nse(item) for item in nses],
        )

    @expose("/", methods=["POST"])
    @protect()
    @safe
    def create(self):
        """
        ---
        post:
          summary: Upload a new NSE script.
          description: |
            Accepts a multipart/form-data request with a single field named
            ``filebody`` containing the .nse file.  The filename must end in
            ``.nse``; the stored script name is derived from the uploaded
            filename (not a separate form field).  If an entry with the same
            name already exists it is updated in-place; duplicate SHA256 hashes
            are rejected.
          requestBody:
            required: true
            content:
              multipart/form-data:
                schema:
                  type: object
                  required:
                    - filebody
                  properties:
                    filebody:
                      type: string
                      format: binary
                      description: The .nse script file to upload.
          responses:
            "200":
              description: Existing NSE script updated successfully.
            "201":
              description: NSE script created successfully.
            "400":
              description: Missing file, wrong extension, or duplicate hash.
        """
        upload = request.files.get("filebody")
        try:
            filename, sha256sum = self._upload_metadata(upload)
        except ValueError as error:
            return self.response_400(message=str(error))

        existing_by_hash = (
            db.session.query(Nses).filter(Nses.hash == sha256sum).one_or_none()
        )
        existing_by_name = (
            db.session.query(Nses).filter(Nses.name == filename).one_or_none()
        )

        if existing_by_hash is not None and (
            existing_by_name is None or existing_by_name.id != existing_by_hash.id
        ):
            return self.response_400(
                message="An NSE script with this file content (SHA256) already exists under a different name"
            )

        file_manager = FileManager()
        item = existing_by_name
        old_filebody = item.filebody if item is not None else None
        new_filebody = None

        if item is not None:
            new_filebody = self._save_uploaded_file(file_manager, item, upload)
            item.filebody = new_filebody
            item.hash = sha256sum
            status = 200
        else:
            item = Nses()
            item.name = filename
            item.hash = sha256sum
            new_filebody = self._save_uploaded_file(file_manager, item, upload)
            item.filebody = new_filebody
            db.session.add(item)
            status = 201

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            self._delete_uploaded_file(file_manager, new_filebody)
            return self._duplicate_value_response()

        if old_filebody and old_filebody != new_filebody:
            self._delete_uploaded_file(file_manager, old_filebody)

        return self.response(
            status,
            result=self._serialize_nse(item),
        )

    @expose("/<int:pk>", methods=["GET"])
    @protect()
    @safe
    def get(self, pk):
        """
        ---
        get:
          summary: Get a single NSE script by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
          responses:
            "200":
              description: NSE script metadata.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
                        properties:
                          id:
                            type: integer
                          name:
                            type: string
                          hash:
                            type: string
            "404":
              description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()
        return self.response(200, result=self._serialize_nse(item))

    @expose("/<int:pk>", methods=["PUT"])
    @protect()
    @safe
    def update(self, pk):
        """
        ---
        put:
          summary: Update an NSE script by ID.
          description: |
            Replace the file content (``filebody``) and/or rename (``name`` form
            field) an existing NSE script.  At least one must be supplied.
            Duplicate SHA256 hashes and name collisions with other records are
            rejected.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
          requestBody:
            required: true
            content:
              multipart/form-data:
                schema:
                  type: object
                  properties:
                    filebody:
                      type: string
                      format: binary
                      description: New .nse script file.
                    name:
                      type: string
                      description: New script name; .nse suffix is appended if omitted.
          responses:
            "200":
              description: NSE script updated successfully.
            "400":
              description: Missing payload, wrong extension, duplicate hash, or name collision.
            "404":
              description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()

        upload = request.files.get("filebody")
        has_upload_field = upload is not None
        has_name_field = "name" in request.form
        new_name = None

        if not has_upload_field and not has_name_field:
            return self.response_400(
                message="Provide at least a new 'filebody' or a new 'name'"
            )

        try:
            if has_name_field:
                new_name = self._normalize_nse_name(
                    request.form.get("name"),
                    append_suffix=True,
                )

                collision = (
                    db.session.query(Nses)
                    .filter(Nses.name == new_name, Nses.id != pk)
                    .one_or_none()
                )
                if collision is not None:
                    raise ValueError(f"An NSE script named '{new_name}' already exists")

            if has_upload_field:
                _, sha256sum = self._upload_metadata(upload)

                collision = (
                    db.session.query(Nses)
                    .filter(Nses.hash == sha256sum, Nses.id != pk)
                    .one_or_none()
                )
                if collision is not None:
                    raise ValueError(
                        "An NSE script with this file content (SHA256) already exists "
                        "under a different name"
                    )
        except ValueError as error:
            return self.response_400(message=str(error))

        file_manager = FileManager()
        old_filebody = item.filebody
        new_filebody = None

        if has_upload_field:
            new_filebody = self._save_uploaded_file(file_manager, item, upload)
            item.filebody = new_filebody
            item.hash = sha256sum

        if new_name is not None:
            item.name = new_name

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            self._delete_uploaded_file(file_manager, new_filebody)
            return self._duplicate_value_response()

        if old_filebody and new_filebody and old_filebody != new_filebody:
            self._delete_uploaded_file(file_manager, old_filebody)

        return self.response(200, result=self._serialize_nse(item))

    @expose("/<int:pk>", methods=["DELETE"])
    @protect()
    @safe
    def delete(self, pk):
        """
        ---
        delete:
          summary: Delete an NSE script by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the NSE script to delete.
          responses:
            "200":
              description: NSE script deleted successfully.
            "404":
              description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()

        file_manager = FileManager()
        old_filebody = item.filebody
        item_name = item.name

        db.session.delete(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self._duplicate_value_response()

        self._delete_uploaded_file(file_manager, old_filebody)
        return self.response(200, message=f"NSE '{item_name}' deleted")


class PortsApi(BaseApi):
    """
    REST API for managing scan ports.

    Provides programmatic equivalents of the /portsview HTML form: list, create,
    read, update, and delete port entries.  All requests and responses are JSON.
    The ``proto`` field in request bodies is the protocol label (e.g. ``"TCP"``);
    the API resolves the matching Protos record internally.
    """

    route_base = "/api/v1/ports"
    openapi_spec_tag = "Ports API"

    @staticmethod
    def _serialize(port):
        return {
            "id": port.id,
            "value": port.value,
            "name": port.name,
            "proto": str(port.proto),
        }

    @staticmethod
    def _normalize_port_value(value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("'value' must be an integer between 1 and 65535")

        if value < 1 or value > 65535:
            raise ValueError("'value' must be an integer between 1 and 65535")

        return value

    @staticmethod
    def _normalize_port_name(value):
        if not isinstance(value, str):
            raise ValueError("'name' must be a non-empty string")

        name = value.strip()
        if not name:
            raise ValueError("'name' must be a non-empty string")

        return name

    @staticmethod
    def _normalize_proto_label(value):
        if not isinstance(value, str):
            raise ValueError("'proto' must be a non-empty string")

        proto_label = value.strip().upper()
        if not proto_label:
            raise ValueError("'proto' must be a non-empty string")

        return proto_label

    @staticmethod
    def _get_proto(proto_label):
        return (
            db.session.query(Protos)
            .filter(func.upper(Protos.value) == proto_label)
            .one_or_none()
        )

    @staticmethod
    def _require_json_object(data):
        if not isinstance(data, dict):
            raise ValueError("JSON body required")

    @staticmethod
    def _require_create_fields(data):
        if not all(field in data for field in ("value", "name", "proto")):
            raise ValueError("Fields 'value', 'name', and 'proto' are required")

    @staticmethod
    def _require_update_fields(data):
        if not any(field in data for field in ("value", "name", "proto")):
            raise ValueError(
                "JSON body with at least one of 'value', 'name', 'proto' required"
            )

    def _validated_create_payload(self, data):
        self._require_json_object(data)
        self._require_create_fields(data)

        port_value = self._normalize_port_value(data["value"])
        name = self._normalize_port_name(data["name"])
        proto_label = self._normalize_proto_label(data["proto"])
        proto = self._get_proto(proto_label)
        if proto is None:
            raise ValueError(f"Unknown protocol '{proto_label}'")

        Ports.check_available(db.session, proto, port_value)

        return port_value, name, proto

    def _validated_update_payload(self, item, data, pk):
        self._require_json_object(data)
        self._require_update_fields(data)

        port_value = item.value
        name = item.name
        proto = item.proto

        if "value" in data:
            port_value = self._normalize_port_value(data["value"])

        if "name" in data:
            name = self._normalize_port_name(data["name"])

        if "proto" in data:
            proto_label = self._normalize_proto_label(data["proto"])
            proto = self._get_proto(proto_label)
            if proto is None:
                raise ValueError(f"Unknown protocol '{proto_label}'")

        Ports.check_available(db.session, proto, port_value, current_id=pk)

        return port_value, name, proto

    @expose("/", methods=["GET"])
    @protect()
    @safe
    def list(self):
        """
        ---
        get:
          summary: List all ports.
          responses:
            "200":
              description: Array of port objects sorted by protocol then port number.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: array
                        items:
                          type: object
                          properties:
                            id:
                              type: integer
                            value:
                              type: integer
                            name:
                              type: string
                            proto:
                              type: string
        """
        ports = (
            db.session.query(Ports)
            .join(Protos, Ports.proto_id == Protos.id)
            .order_by(Protos.value, Ports.value)
            .all()
        )
        return self.response(200, result=[self._serialize(p) for p in ports])

    @expose("/", methods=["POST"])
    @protect()
    @safe
    def create(self):
        """
        ---
        post:
          summary: Create a new port.
          description: |
            Accepts a JSON body with ``value`` (integer 1-65535), ``name``
            (description string), and ``proto`` (protocol label, e.g. ``"TCP"``).
            Returns the created port object with status 201.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - value
                    - name
                    - proto
                  properties:
                    value:
                      type: integer
                      minimum: 1
                      maximum: 65535
                      description: TCP/UDP port number.
                    name:
                      type: string
                      description: Port description.
                    proto:
                      type: string
                      description: Protocol label, for example TCP or UDP.
          responses:
            "201":
              description: Port created successfully.
            "400":
              description: Missing/invalid fields or duplicate port/protocol combination.
        """
        data = request.get_json(silent=True)
        try:
            port_value, name, proto = self._validated_create_payload(data)
        except ValueError as error:
            return self.response_400(message=str(error))

        proto_label = proto.value
        item = Ports(
            value=port_value,
            name=name,
            proto_id=proto.id,
        )
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message=Ports.duplicate_message(proto_label, port_value)
            )
        return self.response(201, result=self._serialize(item))

    @expose("/<int:pk>", methods=["GET"])
    @protect()
    @safe
    def get(self, pk):
        """
        ---
        get:
          summary: Get a single port by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the port to retrieve.
          responses:
            "200":
              description: Port object.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
                        properties:
                          id:
                            type: integer
                          value:
                            type: integer
                          name:
                            type: string
                          proto:
                            type: string
            "404":
              description: Port not found.
        """
        item = db.session.query(Ports).filter(Ports.id == pk).one_or_none()
        if item is None:
            return self.response_404()
        return self.response(200, result=self._serialize(item))

    @expose("/<int:pk>", methods=["PUT"])
    @protect()
    @safe
    def update(self, pk):
        """
        ---
        put:
          summary: Update a port by ID.
          description: |
            Accepts a JSON body with any subset of ``value``, ``name``, and
            ``proto``.  At least one field must be present.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the port to update.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    value:
                      type: integer
                      minimum: 1
                      maximum: 65535
                      description: TCP/UDP port number.
                    name:
                      type: string
                      description: Port description.
                    proto:
                      type: string
                      description: Protocol label, for example TCP or UDP.
          responses:
            "200":
              description: Updated port object.
            "400":
              description: Invalid fields or resulting duplicate combination.
            "404":
              description: Port not found.
        """
        item = db.session.query(Ports).filter(Ports.id == pk).one_or_none()
        if item is None:
            return self.response_404()

        data = request.get_json(silent=True)
        try:
            port_value, name, proto = self._validated_update_payload(item, data, pk)
        except ValueError as error:
            return self.response_400(message=str(error))

        proto_label = str(proto.value)
        item.value = port_value
        item.name = name
        item.proto_id = proto.id
        item.proto = proto
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message=Ports.duplicate_message(proto_label, port_value)
            )
        return self.response(200, result=self._serialize(item))

    @expose("/<int:pk>", methods=["DELETE"])
    @protect()
    @safe
    def delete(self, pk):
        """
        ---
        delete:
          summary: Delete a port by ID.
          parameters:
            - in: path
              name: pk
              required: true
              schema:
                type: integer
              description: ID of the port to delete.
          responses:
            "200":
              description: Port deleted.
            "404":
              description: Port not found.
        """
        item = db.session.query(Ports).filter(Ports.id == pk).one_or_none()
        if item is None:
            return self.response_404()
        label = str(item)
        db.session.delete(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(message=f"Port '{label}' could not be deleted")
        return self.response(200, message=f"Port '{label}' deleted")


class InfoIpApi(BaseApi):
    """Read indexed open ports and co-observed tags for one IP."""

    route_base = "/api/v1/infoip"
    openapi_spec_tag = "IP Scan Summary API"
    DEFAULT_DAYS = 30
    PROTOCOL_BATCH_SIZE = 200

    @staticmethod
    def _two_years_before(value):
        """Return the same UTC instant two calendar years earlier."""
        try:
            return value.replace(year=value.year - 2)
        except ValueError:  # February 29 in a leap year.
            return value.replace(year=value.year - 2, day=28)

    @staticmethod
    def _parse_boundary(value, end_of_day=False):
        """Accept an ISO date or timezone-aware ISO datetime."""
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            boundary = datetime_time.max if end_of_day else datetime_time.min
            return datetime.combine(
                date.fromisoformat(value), boundary, tzinfo=timezone.utc
            )
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Datetime must include a timezone")
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _explicit_window(cls, start, stop, now):
        """Parse paired ISO boundaries, including a whole date-only stop day."""
        if not start or not stop:
            raise ValueError("Both start and stop are required")
        try:
            from_date = cls._parse_boundary(start)
            to_date = cls._parse_boundary(stop, end_of_day=True)
        except ValueError as error:
            raise ValueError("Use ISO dates or timezone-aware ISO datetimes") from error
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", stop) and to_date.date() == now.date():
            to_date = now
        return from_date, to_date

    @classmethod
    def _days_window(cls, days, now):
        """Parse a rolling number of days."""
        if days is None:
            period_days = cls.DEFAULT_DAYS
        elif not re.fullmatch(r"[1-9]\d*", days) or len(days) > 3:
            raise ValueError("days must be a positive integer up to two years")
        else:
            period_days = int(days)
        if period_days > 731:
            raise ValueError("The maximum lookback is two years")
        return now - timedelta(days=period_days), now

    @classmethod
    def _resolve_window(cls, args, now=None):
        """Resolve days or start/stop within the latest two calendar years."""
        now = now or datetime.now(timezone.utc)
        days = args.get("days")
        start = args.get("start")
        stop = args.get("stop")
        if any(len(args.getlist(key)) > 1 for key in ("days", "start", "stop")):
            raise ValueError("Specify each time parameter only once")
        if days is not None and (start is not None or stop is not None):
            raise ValueError("Use either days or start and stop")
        if start is not None or stop is not None:
            from_date, to_date = cls._explicit_window(start, stop, now)
        else:
            from_date, to_date = cls._days_window(days, now)
        if from_date > to_date:
            raise ValueError("start must be before stop")
        if to_date > now:
            raise ValueError("stop cannot be in the future")
        if from_date < cls._two_years_before(now):
            raise ValueError("The maximum lookback is two years")
        return from_date, to_date

    @staticmethod
    def _protocols_from_meili(indexer, uids):
        """Resolve only missing per-report protocols and cache valid pairs."""
        if not uids:
            return {}
        client = meilisearch.Client(
            db.app.config.get("MEILI_DATABASE_URI"),
            db.app.config.get("MEILI_KEY"),
            timeout=5,
        )
        index = client.index("plum")
        resolved = {}
        for offset in range(0, len(uids), InfoIpApi.PROTOCOL_BATCH_SIZE):
            batch = uids[offset : offset + InfoIpApi.PROTOCOL_BATCH_SIZE]
            try:
                page = index.get_documents(
                    {"ids": batch, "fields": ["id", "body.ports"], "limit": len(batch)}
                )
            except meilisearch.errors.MeilisearchError as error:
                logger.warning("InfoIP protocol lookup failed: %s", error)
                break
            docs = []
            for result in page.results:
                raw_doc = dict(result)
                pairs = port_protocol_values(raw_doc)
                if pairs:
                    uid = str(raw_doc["id"])
                    resolved[uid] = set(pairs)
                    docs.append({"uid": uid, "port_protocol": pairs})
            if docs:
                # Automatic reconciliation owns writes once enabled. The API
                # can still return source-derived protocols without altering
                # a pinned (possibly retired) generation.
                managed = isinstance(indexer.r, GenerationClient) and bool(
                    indexer.r.raw.get(CONTROL + "desired")
                )
                if not managed:
                    indexer.replace_field_values_batch("port_protocol", docs)
        return resolved

    @staticmethod
    def _protocol_ports(ports, pairs):
        """Match indexed protocol pairs with port numbers; retain legacy gaps."""
        numbered_ports = {
            int(port)
            for port in ports
            if str(port).isdigit() and 0 <= int(port) <= 65535
        }
        protocol_ports = set()
        for pair in pairs:
            protocol, separator, port = str(pair).partition("/")
            if (
                separator
                and protocol in ("tcp", "udp")
                and port.isdigit()
                and int(port) in numbered_ports
            ):
                protocol_ports.add((int(port), protocol))
        protocol_ports.update(
            (port, None)
            for port in numbered_ports - {port for port, _ in protocol_ports}
        )
        return protocol_ports

    @staticmethod
    def _ports_with_tags(indexer, selected, timestamps):
        """Collect per-port tags and seen bounds from selected HSH reports."""
        if not selected:
            return []
        pipeline = indexer.r.pipeline(transaction=False)
        for uid in selected:
            pipeline.smembers(f"ports:{uid}")
            pipeline.smembers(f"port_protocols:{uid}")
            pipeline.smembers(f"tags:{uid}")
        values = pipeline.execute()
        missing = [
            uid
            for uid, ports, pairs in zip(selected, values[::3], values[1::3])
            if ports and not pairs
        ]
        resolved = InfoIpApi._protocols_from_meili(indexer, missing)
        port_data = {}
        for uid, ports, pairs, tags in zip(
            selected, values[::3], values[1::3], values[2::3]
        ):
            for port, protocol in InfoIpApi._protocol_ports(
                ports, pairs or resolved.get(uid, set())
            ):
                entry = port_data.setdefault(
                    (port, protocol),
                    {
                        "tags": set(),
                        "first_seen": timestamps[uid]["first_seen"],
                        "last_seen": timestamps[uid]["last_seen"],
                    },
                )
                entry["tags"].update(tags)
                entry["first_seen"] = min(
                    entry["first_seen"], timestamps[uid]["first_seen"]
                )
                entry["last_seen"] = max(
                    entry["last_seen"], timestamps[uid]["last_seen"]
                )
        return [
            {
                "port": port,
                "protocol": protocol,
                "tags": sorted(normalize_tags(data["tags"]), key=str.lower),
                "first_seen": datetime.fromtimestamp(data["first_seen"], timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "last_seen": datetime.fromtimestamp(data["last_seen"], timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
            for (port, protocol), data in sorted(
                port_data.items(), key=lambda item: (item[0][0], item[0][1] or "")
            )
        ]

    @expose("/<path:ip>", methods=["GET"])
    @protect()
    @safe
    @prioritized_search
    def get(self, ip):
        """
        ---
        get:
          summary: Get open ports and tags observed for an IP.
          description: |
            Aggregate indexed scan reports whose last_seen is inside the selected
            UTC window. Each protocol/port pair lists tags from reports where that
            port was observed; tags are computed for whole reports, so this does
            not establish that a tag describes that port's service.
            Per-port last_seen is the latest positive observation in the window;
            first_seen is the earliest Kvrocks first_seen among selected HSH reports
            containing that port, and may predate the requested window.
            Legacy reports lacking protocol indexes are resolved from Meilisearch
            for this IP and cached in Kvrocks. If unavailable, protocol is null.
            No continuous openness between scans is implied.
            Default window is the last 30 days. Lookback cannot exceed two years.
          parameters:
            - in: path
              name: ip
              required: true
              schema:
                type: string
              description: One public IPv4 or IPv6 address; CIDR ranges are rejected.
            - in: query
              name: days
              schema:
                type: integer
                minimum: 1
                maximum: 731
                default: 30
              description: Rolling days before now; mutually exclusive with start/stop.
            - in: query
              name: start
              schema:
                type: string
              description: UTC ISO date or timezone-aware datetime; requires stop.
            - in: query
              name: stop
              schema:
                type: string
              description: UTC ISO date or timezone-aware datetime; requires start.
          responses:
            "200":
              description: Distinct open ports with tags co-observed in their reports.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
                        properties:
                          ip:
                            type: string
                          start:
                            type: string
                            format: date-time
                          stop:
                            type: string
                            format: date-time
                          ports:
                            type: array
                            items:
                              type: object
                              properties:
                                port:
                                  type: integer
                                protocol:
                                  type: string
                                  nullable: true
                                  enum: [tcp, udp]
                                tags:
                                  type: array
                                  items:
                                    type: string
                                first_seen:
                                  type: string
                                  format: date-time
                                last_seen:
                                  type: string
                                  format: date-time
                          report_count:
                            type: integer
            "400":
              description: Invalid IP or time parameters.
            "404":
              description: IP has no indexed reports.
            "401":
              description: Authentication required.
            "403":
              description: Permission denied.
        """
        if not is_valid_ip(ip):
            return self.response_400(
                message="Invalid public IP address; CIDR ranges are not accepted"
            )
        try:
            from_date, to_date = self._resolve_window(request.args)
        except ValueError as error:
            return self.response_400(message=str(error))

        normalized_ip = str(ipaddress.ip_address(ip))
        indexer = KVrocksIndexer(
            db.app.config["KVROCKS_HOST"], db.app.config["KVROCKS_PORT"]
        )
        timestamps = indexer.get_timestamp_for_ip(normalized_ip)
        uids = [uid for uid in timestamps if uid not in ("min_seen", "max_seen")]
        if not uids:
            return self.response_404()

        start_ts = int(from_date.timestamp())
        stop_ts = int(to_date.timestamp())
        selected = sorted(
            uid
            for uid in uids
            if timestamps[uid].get("last_seen") is not None
            and start_ts <= timestamps[uid]["last_seen"] <= stop_ts
        )
        return self.response(
            200,
            result={
                "ip": normalized_ip,
                "start": from_date.isoformat().replace("+00:00", "Z"),
                "stop": to_date.isoformat().replace("+00:00", "Z"),
                "ports": self._ports_with_tags(indexer, selected, timestamps),
                "report_count": len(selected),
            },
        )


appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(TargetsApi)
appbuilder.add_api(Api)
appbuilder.add_api(ScanProfilesApi)
appbuilder.add_api(NsesApi)
appbuilder.add_api(PortsApi)
appbuilder.add_api(InfoIpApi)

# Views are initialized before APIs; keep the optional read interface separate.
from .discovery_api import DiscoveryApi  # pylint: disable=wrong-import-position

appbuilder.add_api(DiscoveryApi)
