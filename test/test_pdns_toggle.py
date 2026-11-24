"""Passive DNS switch, legacy startup and incomplete-data behavior."""

import io
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import requests

from app.utils import enrichment_cache, reports, resolved_export
from plum_settings.registry import SettingsError, validate_dependencies
from plum_settings.store import SettingsStore, apply_settings


class PassiveDnsToggleTest(unittest.TestCase):
    """Exercise the switch without contacting CIRCL or Redis."""

    def test_explicit_off_wins_over_credentials_and_blocks_cache(self):
        config = {"PDNS_ENABLED": False, "PASSIVE_USER": "user", "PASSIVE_PWD": "key"}
        with patch.object(enrichment_cache, "cached_response") as cache:
            with self.assertRaises(enrichment_cache.PassiveDNSDisabled):
                enrichment_cache.passive_dns("8.8.8.8", "user", "key", config)
            cache.assert_not_called()

    def test_enabled_requires_both_credentials_on_save(self):
        for credentials in ({}, {"PASSIVE_USER": "user"}, {"PASSIVE_PWD": "key"}):
            with self.subTest(credentials=credentials), self.assertRaises(
                SettingsError
            ):
                validate_dependencies(
                    {
                        "PDNS_ENABLED": True,
                        **credentials,
                        "TAG_RECONCILIATION_MIN_PLANNING_BATCH_SIZE": 25,
                        "TAG_RECONCILIATION_PLANNING_BATCH_SIZE": 1000,
                        "TAG_RECONCILIATION_QUIET_SECONDS": 2,
                        "TAG_RECONCILIATION_IDLE_SECONDS": 15,
                    }
                )

    def test_legacy_credentials_are_inferred_but_explicit_off_is_preserved(self):
        with TemporaryDirectory() as directory, patch.dict(
            os.environ, {"PLUM_SETTINGS_DIR": directory}
        ):
            for flag, expected in ((None, True), (False, False)):
                with self.subTest(flag=flag):
                    config = {"PASSIVE_USER": "user", "PASSIVE_PWD": "key"}
                    if flag is not None:
                        config["PDNS_ENABLED"] = flag
                    self.assertEqual(
                        apply_settings(config).applied["PDNS_ENABLED"], expected
                    )

    def test_legacy_saved_credential_overrides_are_inferred(self):
        with TemporaryDirectory() as directory, patch.dict(
            os.environ, {"PLUM_SETTINGS_DIR": directory}
        ):
            store = SettingsStore(Path(directory))
            store.save("0", {"PASSIVE_USER": "user", "PASSIVE_PWD": "key"}, {})
            config = {}
            self.assertTrue(apply_settings(config).applied["PDNS_ENABLED"])

    def test_authentication_and_timeout_errors_have_distinct_codes(self):
        with patch.object(enrichment_cache.requests, "get") as get:
            get.return_value.__enter__.return_value.status_code = 401
            with self.assertRaises(enrichment_cache.PassiveDNSAuthenticationError):
                enrichment_cache._pdns_source("8.8.8.8", "user", "bad-key")
            get.side_effect = requests.Timeout("timed out")
            with self.assertRaises(enrichment_cache.PassiveDNSTimeout):
                enrichment_cache._pdns_source("8.8.8.8", "user", "key")

    def test_disabled_report_skips_lookup_and_failed_report_warns_once(self):
        disabled = {"PDNS_ENABLED": False, "PASSIVE_USER": "user", "PASSIVE_PWD": "key"}
        warnings = []
        with patch.object(reports, "cached_passive_dns") as lookup:
            self.assertEqual(
                reports.collect_report_passive_dns_fqdns(
                    disabled, ["8.8.8.8"], {}, warning_callback=warnings.append
                ),
                {},
            )
            lookup.assert_not_called()
            lookup.side_effect = enrichment_cache.PassiveDNSTimeout("timed out")
            enabled = {**disabled, "PDNS_ENABLED": True}
            self.assertEqual(
                reports.collect_report_passive_dns_fqdns(
                    enabled,
                    ["8.8.8.8", "1.1.1.1"],
                    {},
                    warning_callback=warnings.append,
                ),
                {},
            )
        self.assertEqual(len(warnings), 1)
        self.assertIn("2 IP lookup(s) failed", warnings[0])

    def test_disabled_export_keeps_rows_without_pdns_or_warning(self):
        warnings = []
        output = io.StringIO(newline="")
        results = {"results": {"8.8.8.8": []}, "time_range": {}, "timestamps": {}}
        config = {"PDNS_ENABLED": False, "PASSIVE_USER": "user", "PASSIVE_PWD": "key"}
        with patch.object(resolved_export, "lookup_pdns") as lookup, patch.object(
            resolved_export, "collect_report_ptr_fqdns", return_value={"8.8.8.8": []}
        ):
            resolved_export.write_resolved_csv(
                output,
                results,
                config,
                lambda _done: None,
                warnings.append,
                document_loader=lambda _uid: {},
            )
            lookup.assert_not_called()
        self.assertEqual(warnings, [])
        self.assertIn("8.8.8.8", output.getvalue())


if __name__ == "__main__":
    unittest.main()
