"""Regression checks for report schedule periods."""

import sys
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webapp"))

from app.utils.reports import (  # pylint: disable=wrong-import-position
    compute_next_report_run,
    compute_previous_report_interval,
    compute_report_interval,
)


class ReportIntervalTest(unittest.TestCase):
    """A report period follows its schedule type, not its delivery history."""

    def test_monthly_uses_previous_calendar_month_despite_last_run(self):
        report = SimpleNamespace(
            schedule_type="monthly",
            last_run_at=datetime(2026, 9, 13, 8, 0),
        )
        run_at = datetime(2026, 9, 15, 10, 4, 5)

        self.assertEqual(
            compute_report_interval(report, run_at),
            (datetime(2026, 8, 15, 10, 4, 5), run_at),
        )
        self.assertEqual(
            compute_previous_report_interval(report, *compute_report_interval(report, run_at)),
            (datetime(2026, 7, 15, 10, 4, 5), datetime(2026, 8, 15, 10, 4, 5)),
        )

    def test_weekly_uses_previous_seven_days_and_weekly_next_run(self):
        report = SimpleNamespace(schedule_type="weekly", schedule_day=1, schedule_hour=8)
        run_at = datetime(2026, 9, 15, 10, 4, 5)  # Tuesday
        from_dt, to_dt = compute_report_interval(report, run_at)

        self.assertEqual((from_dt, to_dt), (datetime(2026, 9, 8, 10, 4, 5), run_at))
        self.assertEqual(
            compute_previous_report_interval(report, from_dt, to_dt),
            (datetime(2026, 9, 1, 10, 4, 5), datetime(2026, 9, 8, 10, 4, 5)),
        )
        self.assertEqual(
            compute_next_report_run(report, run_at), datetime(2026, 9, 21, 8, 0)
        )
