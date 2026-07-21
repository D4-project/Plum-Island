#!/usr/bin/env python3
"""Regression tests for scan-profile Nmap additional parameters."""

# pylint: disable=wrong-import-position,missing-function-docstring,duplicate-code,import-error

import os
import sys
from types import SimpleNamespace
from unittest import TestCase, main

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.apis import _build_job_nmap_additional_params_payload
from app.models import ScanProfiles, validate_nmap_additional_params


class NmapAdditionalParamsValidationTest(TestCase):
    """Test safe storage of optional Nmap argv input."""

    def test_valid_params_are_trimmed_and_preserved(self):
        value = "  --min-hostgroup 32 --host-timeout 5m  "
        self.assertEqual(
            validate_nmap_additional_params(value),
            "--min-hostgroup 32 --host-timeout 5m",
        )

    def test_empty_values_become_none(self):
        self.assertIsNone(validate_nmap_additional_params(None))
        self.assertIsNone(validate_nmap_additional_params("   "))

    def test_profile_uses_same_validation(self):
        profile = ScanProfiles(
            name="FQDN profile",
            nmap_additional_params="--min-hostgroup 32 --host-timeout 5m",
        )
        self.assertEqual(
            profile.nmap_additional_params,
            "--min-hostgroup 32 --host-timeout 5m",
        )

    def test_shell_control_syntax_is_rejected(self):
        for value in (
            "--host-timeout 5m; touch /tmp/marker",
            "--host-timeout $(cat /tmp/value)",
            "--host-timeout 5m > /tmp/output",
            "--host-timeout 5m\\;",
            "--host-timeout 5m\n--min-hostgroup 32",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_nmap_additional_params(value)

    def test_unbalanced_quotes_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_nmap_additional_params('--script "safe.nse')

    def test_length_is_bounded(self):
        with self.assertRaises(ValueError):
            validate_nmap_additional_params("--flag " + ("x" * 4096))


class NmapAdditionalParamsPayloadTest(TestCase):
    """Test additive API payload behavior for old and new jobs."""

    def test_new_job_value_is_serialized(self):
        job = SimpleNamespace(nmap_additional_params="--host-timeout 5m")
        self.assertEqual(
            _build_job_nmap_additional_params_payload(job),
            "--host-timeout 5m",
        )

    def test_legacy_job_without_column_is_tolerated(self):
        self.assertIsNone(_build_job_nmap_additional_params_payload(SimpleNamespace()))

    def test_null_value_is_serialized_as_none(self):
        job = SimpleNamespace(nmap_additional_params=None)
        self.assertIsNone(_build_job_nmap_additional_params_payload(job))


if __name__ == "__main__":
    main()
