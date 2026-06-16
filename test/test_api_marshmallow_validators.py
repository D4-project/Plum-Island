#!/usr/bin/env python3
"""
Regression tests for API Marshmallow validators.
"""

# pylint: disable=protected-access

import os
import sys
from unittest import TestCase, main

from marshmallow import ValidationError

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.apis import BotInfoSchema, NsesApi  # pylint: disable=wrong-import-position


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


if __name__ == "__main__":
    main()
