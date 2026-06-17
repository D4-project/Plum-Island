#!/usr/bin/env python3
"""
Regression tests for API Marshmallow validators.
"""

# pylint: disable=protected-access,wrong-import-position

import os
import sys
from unittest import TestCase, main

from marshmallow import ValidationError

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.apis import (
    BotInfoSchema,
    NsesApi,
    PortsApi,
    ScanProfilesApi,
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


class ScanProfilesApiValidationTest(TestCase):
    """Tests for ScanProfiles API input normalization helpers."""

    def test_normalize_profile_name_strips_whitespace(self):
        """Profile names are normalized before storage."""
        self.assertEqual(
            ScanProfilesApi._normalize_profile_name(" All TCP ", "bad"),
            "All TCP",
        )

    def test_normalize_profile_name_rejects_empty_values(self):
        """Blank or non-string names are invalid."""
        for value in ("", "   ", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ScanProfilesApi._normalize_profile_name(value, "bad")

    def test_normalize_positive_integer_rejects_bool_and_invalid_values(self):
        """Positive integer fields must not accept bools or strings."""
        self.assertEqual(
            ScanProfilesApi._normalize_positive_integer(720, "scan_cycle_minutes"),
            720,
        )
        for value in (0, -1, "720", True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ScanProfilesApi._normalize_positive_integer(
                        value,
                        "scan_cycle_minutes",
                    )

    def test_normalize_priority_rejects_bool_and_out_of_range(self):
        """Priority only accepts the scheduler priority values."""
        self.assertEqual(ScanProfilesApi._normalize_priority(0), 0)
        self.assertEqual(ScanProfilesApi._normalize_priority(4), 4)
        for value in (-1, 5, "1", True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ScanProfilesApi._normalize_priority(value)

    def test_normalize_boolean_is_strict(self):
        """JSON boolean fields must not coerce arbitrary truthy values."""
        self.assertTrue(ScanProfilesApi._normalize_boolean(True, "apply_to_all"))
        self.assertFalse(ScanProfilesApi._normalize_boolean(False, "apply_to_all"))
        for value in ("false", 1, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ScanProfilesApi._normalize_boolean(value, "apply_to_all")

    def test_normalize_id_list_deduplicates_valid_ids(self):
        """Relationship ID lists keep input order while removing duplicates."""
        self.assertEqual(
            ScanProfilesApi._normalize_id_list([3, 1, 3], "port_ids"),
            [3, 1],
        )

    def test_normalize_id_list_rejects_invalid_values(self):
        """ID lists must be lists of positive integers."""
        for value in ("123", [0], [-1], [True], [None]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ScanProfilesApi._normalize_id_list(value, "port_ids")

    def test_normalize_id_list_can_require_at_least_one_port(self):
        """Scan profile create/update cannot leave the profile without ports."""
        with self.assertRaises(ValueError):
            ScanProfilesApi._normalize_id_list(
                [],
                "port_ids",
                allow_empty=False,
            )


if __name__ == "__main__":
    main()
