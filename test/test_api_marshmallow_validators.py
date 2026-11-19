#!/usr/bin/env python3
"""
Regression tests for API Marshmallow validators.
"""

# pylint: disable=protected-access,wrong-import-position

import os
import sys
from datetime import datetime
from types import SimpleNamespace
from unittest import TestCase, main

from marshmallow import ValidationError

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.apis import (
    BotInfoSchema,
    BotJobReleaseSchema,
    NsesApi,
    PortsApi,
    _release_interrupted_job,
)


class BotInfoSchemaValidationTest(TestCase):
    """Tests for BotInfoSchema field validators."""

    def test_invalid_uid_raises_validation_error(self):
        """Malformed UID must be a 400-style validation error, not TypeError."""
        with self.assertRaises(ValidationError) as context:
            BotInfoSchema().load({"UID": "bad"}, partial=True)

        self.assertEqual(context.exception.messages, {"UID": ["Invalid UID"]})

    def test_invalid_job_uid_raises_validation_error(self):
        """Malformed JOB_UID must be a validation error, not TypeError."""
        with self.assertRaises(ValidationError) as context:
            BotInfoSchema().load({"JOB_UID": "bad"}, partial=True)

        self.assertEqual(context.exception.messages, {"JOB_UID": ["Invalid JOB_UID"]})


class BotJobReleaseSchemaValidationTest(TestCase):
    """Tests for interrupted job release request validation."""

    def test_release_schema_does_not_require_ext_ip(self):
        """Interrupted job release only needs bot auth and job UID."""
        self.assertNotIn("EXT_IP", BotJobReleaseSchema().fields)

    def test_invalid_release_job_uid_raises_validation_error(self):
        """Malformed release JOB_UID must be rejected."""
        with self.assertRaises(ValidationError) as context:
            BotJobReleaseSchema().load({"JOB_UID": "bad"}, partial=True)

        self.assertEqual(context.exception.messages, {"JOB_UID": ["Invalid JOB_UID"]})


class BotJobReleaseStateTest(TestCase):
    """Tests for interrupted job state transitions."""

    def test_release_assigned_active_job_requeues_and_clears_bot_id(self):
        """Active job assigned to requesting bot is returned to waiting queue."""
        now = datetime(2026, 7, 9, 12, 0, 0)
        bot = SimpleNamespace(id=3, running=True, last_seen=None)
        job = SimpleNamespace(
            active=True,
            finished=False,
            bot_id=3,
            job_start=datetime(2026, 7, 9, 11, 0, 0),
        )

        released, state = _release_interrupted_job(job, bot, now)

        self.assertTrue(released)
        self.assertEqual(state, "released")
        self.assertFalse(job.active)
        self.assertIsNone(job.bot_id)
        self.assertIsNone(job.job_start)
        self.assertFalse(bot.running)
        self.assertEqual(bot.last_seen, now)

    def test_release_job_assigned_to_other_bot_is_rejected(self):
        """Active job assigned to another bot must not be mutated."""
        now = datetime(2026, 7, 9, 12, 0, 0)
        bot = SimpleNamespace(id=3, running=True, last_seen=None)
        job_start = datetime(2026, 7, 9, 11, 0, 0)
        job = SimpleNamespace(
            active=True,
            finished=False,
            bot_id=4,
            job_start=job_start,
        )

        released, state = _release_interrupted_job(job, bot, now)

        self.assertFalse(released)
        self.assertEqual(state, "forbidden")
        self.assertTrue(job.active)
        self.assertEqual(job.bot_id, 4)
        self.assertEqual(job.job_start, job_start)
        self.assertTrue(bot.running)
        self.assertIsNone(bot.last_seen)

    def test_release_already_requeued_job_is_idempotent(self):
        """Already released queued jobs return success without mutation."""
        now = datetime(2026, 7, 9, 12, 0, 0)
        bot = SimpleNamespace(id=3, running=True, last_seen=None)
        job = SimpleNamespace(
            active=False,
            finished=False,
            bot_id=None,
            job_start=None,
        )

        released, state = _release_interrupted_job(job, bot, now)

        self.assertTrue(released)
        self.assertEqual(state, "already released")
        self.assertFalse(job.active)
        self.assertIsNone(job.bot_id)
        self.assertIsNone(job.job_start)
        self.assertTrue(bot.running)
        self.assertIsNone(bot.last_seen)

    def test_release_inactive_job_still_assigned_to_bot_clears_assignment(self):
        """Inactive unfinished job still assigned to the bot is released."""
        now = datetime(2026, 7, 9, 12, 0, 0)
        bot = SimpleNamespace(id=3, running=True, last_seen=None)
        job = SimpleNamespace(
            active=False,
            finished=False,
            bot_id=3,
            job_start=datetime(2026, 7, 9, 11, 0, 0),
        )

        released, state = _release_interrupted_job(job, bot, now)

        self.assertTrue(released)
        self.assertEqual(state, "already released")
        self.assertFalse(job.active)
        self.assertIsNone(job.bot_id)
        self.assertIsNone(job.job_start)
        self.assertFalse(bot.running)
        self.assertEqual(bot.last_seen, now)


class NsesApiValidationTest(TestCase):
    """Tests for NSE API input normalization helpers."""

    def test_normalize_nse_name_strips_paths(self):
        """Path-like names must not be stored verbatim."""
        self.assertEqual(
            NsesApi._normalize_nse_name("../../script.nse"),
            "script.nse",
        )

    def test_normalize_nse_name_appends_suffix_for_form_names(self):
        """PUT rename accepts bare names and normalizes to .nse."""
        self.assertEqual(
            NsesApi._normalize_nse_name("script", append_suffix=True),
            "script.nse",
        )

    def test_normalize_nse_name_rejects_empty_name(self):
        """Blank or suffix-only names are invalid."""
        for value in ("", "   ", ".nse"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    NsesApi._normalize_nse_name(value, append_suffix=True)


class PortsApiValidationTest(TestCase):
    """Tests for Ports API input normalization helpers."""

    def test_normalize_port_value_accepts_valid_boundaries(self):
        """Valid TCP/UDP port boundaries are accepted unchanged."""
        self.assertEqual(PortsApi._normalize_port_value(1), 1)
        self.assertEqual(PortsApi._normalize_port_value(65535), 65535)

    def test_normalize_port_value_rejects_invalid_values(self):
        """Non-integers, bools, and out-of-range ports are invalid."""
        for value in (0, 65536, "22", True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PortsApi._normalize_port_value(value)

    def test_normalize_port_name_strips_whitespace(self):
        """Descriptions are normalized before storage."""
        self.assertEqual(PortsApi._normalize_port_name(" SSH "), "SSH")

    def test_normalize_port_name_rejects_empty_values(self):
        """Blank or non-string descriptions are invalid."""
        for value in ("", "   ", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PortsApi._normalize_port_name(value)

    def test_normalize_proto_label_uppercases_and_strips(self):
        """Protocol labels are matched case-insensitively."""
        self.assertEqual(PortsApi._normalize_proto_label(" tcp "), "TCP")

    def test_normalize_proto_label_rejects_empty_values(self):
        """Blank or non-string protocol labels are invalid."""
        for value in ("", "   ", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PortsApi._normalize_proto_label(value)

    def test_proto_to_port_uses_model_tuple_format(self):
        """Generated uniqueness value follows the model-documented format."""
        self.assertEqual(PortsApi._proto_to_port(22, 1), "22:1")


if __name__ == "__main__":
    main()
