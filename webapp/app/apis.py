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
import hashlib
import os
import json
import logging
import time
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi
from flask_appbuilder.api import API_RESULT_RES_KEY, BaseApi, expose, safe, protect
from flask_appbuilder.filemanager import FileManager
from flask import request

from sqlalchemy import func, distinct
from sqlalchemy.exc import IntegrityError, NoResultFound
from werkzeug.security import check_password_hash
from marshmallow import Schema, fields, validates, ValidationError
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
from .utils.timeutils import utcnow_naive, ensure_utc_naive
from .utils.scan_cycles import reconcile_scanprofile_cycle
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
    JOB_UID = fields.String(
        required=False,
        metadata={"description": "Uid of the scan"},
    )
    NSE_HASHES = fields.Dict(
        required=False,
        keys=fields.String(),
        values=fields.String(),
        metadata={"description": "Cached NSE SHA256 hashes keyed by NSE filename"},
    )

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


def _claim_job_for_bot(job_id, bot_id, now):
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
        )
        .update(
            {
                Jobs.active: True,
                Jobs.job_start: now,
                Jobs.bot_id: bot_id,
            },
            synchronize_session=False,
        )
    )


def _get_available_job_priorities():
    """
    Return the priority queues that currently have at least one waiting job.
    """
    rows = (
        db.session.query(Jobs.priority)
        .filter(Jobs.active == False, Jobs.finished == False)
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
                    API_RESULT_RES_KEY: self.add_model_schema.dump(item, many=False),
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
                    Bots.last_seen: utcnow_naive(),
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
        job_bot = _get_bot_by_uid(botinfo.get("UID"))
        if job_bot is None:
            logger.warning(
                "Unknown or inactive bot %s requested a job", botinfo.get("UID")
            )
            return self.response(403, message="forbidden")

        # Get one job to do using smooth weighted round-robin over non-empty
        # priority queues. Priority 4 gets the largest share when present, but
        # lower queues inherit capacity when higher queues are empty.
        prio_list = _select_weighted_priority(_get_available_job_priorities())
        job_todo = None
        for prio in prio_list:
            candidate = (
                db.session.query(Jobs)
                .filter(
                    Jobs.active == False, Jobs.finished == False, Jobs.priority == prio
                )
                .order_by(Jobs.job_creation.asc())  # oldest first
                .first()
            )
            if not candidate:
                continue

            now = utcnow_naive()
            if _claim_job_for_bot(candidate.id, job_bot.id, now) != 1:
                db.session.rollback()
                continue

            job_todo = candidate
            job_todo.active = True
            job_todo.job_start = now
            job_todo.bot_id = job_bot.id
            job_bot.running = True  # Set the Bot to Active too
            job_bot.last_seen = now
            db.session.add(job_bot)
            db.session.add(job_todo)
            if job_todo:
                break  # A soon as a Job is found... return.

        # Now whe have maybe a job to launch.
        if job_todo:
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

            ret_msg = {
                "message": "ready",
                "job": job_todo.job,
                "job_uid": job_todo.uid,
                "nmap_nse": nmap_nse,
                "nse_scripts": nse_scripts,
                "nmap_ports": (
                    job_todo.scan_ports.split(",") if job_todo.scan_ports else []
                ),
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
                "Bot %s tried to submit job %s assigned to bot_id %s",
                botinfo.get("UID"),
                job_bot.uid,
                job_bot.bot_id,
            )
            return self.response(403, message="forbidden")

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
        if elapsed_seconds < MIN_JOB_RUNTIME_SECONDS:
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
            reconcile_scanprofile_cycle(job_bot.scanprofile_id)
        commit_started = time.perf_counter()
        db.session.commit()
        logger.debug(
            "sndjob debug: commit for job %s completed in %.2fs (total_request=%.2fs)",
            job_bot.uid,
            time.perf_counter() - commit_started,
            time.perf_counter() - request_started,
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
        "port_ids",
        "nse_ids",
        "scan_cycle_minutes",
        "priority",
        "apply_to_all",
    }

    @staticmethod
    def _serialize(profile):
        return {
            "id": profile.id,
            "name": profile.name,
            "scan_cycle_minutes": profile.scan_cycle_minutes,
            "priority": profile.priority,
            "apply_to_all": profile.apply_to_all,
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
          summary: List all scan profiles.
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
        """
        profiles = (
            db.session.query(ScanProfiles).order_by(ScanProfiles.name.asc()).all()
        )
        return self.response(
            200, result=[self._serialize(profile) for profile in profiles]
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
            and ``apply_to_all`` (boolean, default false).
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
            "400":
              description: Missing/invalid fields or duplicate name.
        """
        data = request.get_json(silent=True)
        try:
            payload = self._validated_create_payload(data)
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
            ``nse_ids``, ``scan_cycle_minutes``, ``priority``, and
            ``apply_to_all``. At least one supported field must be present.
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

        data = request.get_json(silent=True)
        try:
            payload = self._validated_update_payload(data, pk)
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
    def _proto_to_port(port_value, proto_id):
        return f"{port_value}:{proto_id}"

    @staticmethod
    def _get_proto(proto_label):
        return (
            db.session.query(Protos)
            .filter(func.upper(Protos.value) == proto_label)
            .one_or_none()
        )

    @staticmethod
    def _port_exists(port_value, proto_id, current_id=None):
        query = db.session.query(Ports).filter(
            Ports.value == port_value,
            Ports.proto_id == proto_id,
        )
        if current_id is not None:
            query = query.filter(Ports.id != current_id)
        return query.first() is not None

    @staticmethod
    def _duplicate_message(proto_label, port_value):
        return f"Port {proto_label}:{port_value} already exists"

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

        if self._port_exists(port_value, proto.id):
            raise ValueError(self._duplicate_message(proto_label, port_value))

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

        proto_label = str(proto.value)
        if self._port_exists(port_value, proto.id, current_id=pk):
            raise ValueError(self._duplicate_message(proto_label, port_value))

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

        item = Ports(
            value=port_value,
            name=name,
            proto_id=proto.id,
            proto_to_port=self._proto_to_port(port_value, proto.id),
        )
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            proto_label = str(proto.value)
            return self.response_400(
                message=self._duplicate_message(proto_label, port_value)
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
        item.proto_to_port = self._proto_to_port(port_value, proto.id)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return self.response_400(
                message=self._duplicate_message(proto_label, port_value)
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


appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(TargetsApi)
appbuilder.add_api(Api)
appbuilder.add_api(ScanProfilesApi)
appbuilder.add_api(NsesApi)
appbuilder.add_api(PortsApi)
