"""
Tests for scan-unit progress helpers.
"""

import unittest

# pylint: disable=missing-function-docstring,protected-access

from app.models import ScanProfileCycles
from app.utils.mutils import (
    MAX_SCAN_UNIT_COUNT,
    compute_scan_unit_count,
    compute_scan_unit_count_list,
)


class ScanUnitCountTest(unittest.TestCase):
    """
    Validate target and job scan-unit counters.
    """

    def test_single_hosts_count_as_one(self):
        self.assertEqual(compute_scan_unit_count("8.8.8.8"), 1)
        self.assertEqual(compute_scan_unit_count("example.com"), 1)
        self.assertEqual(compute_scan_unit_count("example.com."), 1)

    def test_cidr_counts_addresses(self):
        self.assertEqual(compute_scan_unit_count("8.8.8.0/24"), 256)
        self.assertEqual(compute_scan_unit_count("8.8.8.8/24"), 256)

    def test_job_list_sums_items(self):
        self.assertEqual(
            compute_scan_unit_count_list("8.8.8.0/25,example.com,1.1.1.1"),
            130,
        )

    def test_huge_ranges_are_capped(self):
        self.assertEqual(compute_scan_unit_count("2000::/1"), MAX_SCAN_UNIT_COUNT)

    def test_cycle_percent_is_bounded(self):
        self.assertEqual(ScanProfileCycles._format_percent(150, 100), 100.0)
        self.assertEqual(ScanProfileCycles._format_percent(-1, 100), 0.0)
        self.assertEqual(ScanProfileCycles._format_percent(25, 100), 25.0)


if __name__ == "__main__":
    unittest.main()
