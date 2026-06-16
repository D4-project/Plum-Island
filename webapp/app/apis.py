"""
 .--. .---. .-.                     .-.
: .; :: .; :: :                     : :
:    ::  _.': :       .--.  .--.  .-' : .--.
: :: :: :   : :      '  ..'' .; :' .; :' '_.'
:_;:_;:_;   :_;      `.__.'`.__.'`.__.'`.__.'

This module contains all code related to API's.
"""

import base64
import hashlib
import os
import json
import logging
import time
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder import ModelRestApi, has_access
from flask_appbuilder.api import BaseApi, expose, safe, protect
from flask_appbuilder.filemanager import FileManager
from flask_appbuilder.api import API_RESULT_RES_KEY, BaseApi, expose, safe, protect
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


class NsesApi(BaseApi):
    """
    REST API for managing NSE (Nmap Script Engine) scripts.

    Provides programmatic equivalents of the /nsesview HTML form: list, create,
    and delete NSE entries.  File upload uses multipart/form-data; all other
    responses are JSON.
    """

    route_base = "/api/v1/nses"
    openapi_spec_tag = "NSE Scripts API"

    @expose("/", methods=["GET"])
    @protect()
    @safe
    def list(self):
        """
        summary: List all NSE scripts.
        responses:
            200:
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
            result=[{"id": n.id, "name": n.name, "hash": n.hash} for n in nses],
        )

    @expose("/", methods=["POST"])
    @protect()
    @safe
    def create(self):
        """
        summary: Upload a new NSE script.
        description: |
            Accepts a multipart/form-data request with a single field named
            ``filebody`` containing the .nse file.  The filename must end in
            ``.nse``; the stored script name is derived from the uploaded
            filename (not a separate form field).  If an entry with the same
            name already exists it is updated in-place; duplicate SHA256 hashes
            are rejected.
        parameters:
            - in: formData
              name: filebody
              required: true
              type: file
              description: The .nse script file to upload.
        responses:
            201:
                description: NSE script created or updated successfully.
            400:
                description: Missing file, wrong extension, or duplicate hash.
        """
        upload = request.files.get("filebody")
        if not upload or not getattr(upload, "filename", ""):
            return self.response_400(message="Field 'filebody' with a .nse file is required")

        filename = os.path.basename(upload.filename)
        if not filename.lower().endswith(".nse"):
            return self.response_400(message="Only .nse files are allowed")

        file_bytes = upload.read()
        upload.stream.seek(0)
        sha256sum = hashlib.sha256(file_bytes).hexdigest()

        existing_by_hash = db.session.query(Nses).filter(Nses.hash == sha256sum).one_or_none()
        existing_by_name = db.session.query(Nses).filter(Nses.name == filename).one_or_none()

        if existing_by_hash is not None and (
            existing_by_name is None or existing_by_name.id != existing_by_hash.id
        ):
            return self.response_400(
                message="An NSE script with this file content (SHA256) already exists under a different name"
            )

        file_manager = FileManager()
        item = existing_by_name

        if item is not None:
            # Update: replace file on disk and refresh hash.
            if item.filebody:
                file_manager.delete_file(item.filebody)
            stored_name = file_manager.generate_name(item, upload)
            item.filebody = file_manager.save_file(upload, stored_name)
            item.hash = sha256sum
            db.session.commit()
            status = 200
        else:
            item = Nses()
            item.name = filename
            item.hash = sha256sum
            stored_name = file_manager.generate_name(item, upload)
            item.filebody = file_manager.save_file(upload, stored_name)
            db.session.add(item)
            db.session.commit()
            status = 201

        return self.response(
            status,
            result={"id": item.id, "name": item.name, "hash": item.hash},
        )

    @expose("/<int:pk>", methods=["GET"])
    @protect()
    @safe
    def get(self, pk):
        """
        summary: Get a single NSE script by ID.
        parameters:
            - in: path
              name: pk
              required: true
              schema:
                  type: integer
        responses:
            200:
                description: NSE script metadata.
            404:
                description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()
        return self.response(200, result={"id": item.id, "name": item.name, "hash": item.hash})

    @expose("/<int:pk>", methods=["PUT"])
    @protect()
    @safe
    def update(self, pk):
        """
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
            - in: formData
              name: filebody
              required: false
              type: file
              description: New .nse script file.
            - in: formData
              name: name
              required: false
              type: string
              description: New script name (must end in .nse; suffix appended if omitted).
        responses:
            200:
                description: NSE script updated successfully.
            400:
                description: Missing payload, wrong extension, duplicate hash, or name collision.
            404:
                description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()

        upload = request.files.get("filebody")
        new_name = request.form.get("name")

        if not upload and not new_name:
            return self.response_400(message="Provide at least a new 'filebody' or a new 'name'")

        if upload and getattr(upload, "filename", ""):
            filename = os.path.basename(upload.filename)
            if not filename.lower().endswith(".nse"):
                return self.response_400(message="Only .nse files are allowed")
            file_bytes = upload.read()
            upload.stream.seek(0)
            sha256sum = hashlib.sha256(file_bytes).hexdigest()
            collision = (
                db.session.query(Nses)
                .filter(Nses.hash == sha256sum, Nses.id != pk)
                .one_or_none()
            )
            if collision is not None:
                return self.response_400(
                    message="An NSE script with this file content (SHA256) already exists under a different name"
                )
            file_manager = FileManager()
            if item.filebody:
                file_manager.delete_file(item.filebody)
            stored_name = file_manager.generate_name(item, upload)
            item.filebody = file_manager.save_file(upload, stored_name)
            item.hash = sha256sum

        if new_name:
            if not new_name.lower().endswith(".nse"):
                new_name = f"{new_name}.nse"
            collision = (
                db.session.query(Nses)
                .filter(Nses.name == new_name, Nses.id != pk)
                .one_or_none()
            )
            if collision is not None:
                return self.response_400(message=f"An NSE script named '{new_name}' already exists")
            item.name = new_name

        db.session.commit()
        return self.response(200, result={"id": item.id, "name": item.name, "hash": item.hash})

    @expose("/<int:pk>", methods=["DELETE"])
    @protect()
    @safe
    def delete(self, pk):
        """
        summary: Delete an NSE script by ID.
        parameters:
            - in: path
              name: pk
              required: true
              schema:
                  type: integer
              description: ID of the NSE script to delete.
        responses:
            200:
                description: NSE script deleted successfully.
            404:
                description: NSE script not found.
        """
        item = db.session.query(Nses).filter(Nses.id == pk).one_or_none()
        if item is None:
            return self.response_404()

        file_manager = FileManager()
        if item.filebody:
            file_manager.delete_file(item.filebody)

        db.session.delete(item)
        db.session.commit()
        return self.response(200, message=f"NSE '{item.name}' deleted")


appbuilder.add_api(PublicTargetsApi)
appbuilder.add_api(TargetsApi)
appbuilder.add_api(Api)
appbuilder.add_api(NsesApi)
