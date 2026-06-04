#!/usr/bin/env python3
"""
Regression tests for API Marshmallow validators.
"""

import os
import sys
from unittest import TestCase, main

from marshmallow import ValidationError

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.apis import BotInfoSchema  # pylint: disable=wrong-import-position


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

    def test_valid_uid_passes(self):
        """A well-formed UUID4 string must not raise ValidationError."""
        try:
            BotInfoSchema().load(
                {"UID": "550e8400-e29b-41d4-a716-446655440000"}, partial=True
            )
        except ValidationError as exc:
            self.fail(f"Valid UID unexpectedly raised: {exc}")

    def test_private_ip_rejected(self):
        """A private IP address must be rejected on EXT_IP."""
        with self.assertRaises(ValidationError) as context:
            BotInfoSchema().load({"EXT_IP": "192.168.1.1"}, partial=True)
        self.assertIn("EXT_IP", context.exception.messages)

    def test_short_agent_key_rejected(self):
        """An AGENT_KEY shorter than 80 characters must raise ValidationError."""
        with self.assertRaises(ValidationError) as context:
            BotInfoSchema().load({"AGENT_KEY": "tooshort"}, partial=True)
        self.assertIn("AGENT_KEY", context.exception.messages)


if __name__ == "__main__":
    main()
