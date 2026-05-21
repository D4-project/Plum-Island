#!/usr/bin/env python3
"""
Regression tests for API Marshmallow validators.
"""

import os
import sys
from unittest import TestCase, main

from marshmallow import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webapp"))

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


if __name__ == "__main__":
    main()
