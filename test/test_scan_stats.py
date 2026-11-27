"""Exact-once counters, atomic rollback, UTC grouping and portable schema."""

import runpy
import sqlite3
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import Mock

from app.models import IngestionStatSample, Jobs, ScanStatBucket
from app.utils.scan_stats import (
    activity_series,
    claim_completed_job,
    count_open_ports,
    increment_completed_counters,
    ingestion_series,
    job_targeted_ports,
    report_counts,
    sample_ingestion_queue,
)
from sqlalchemy import create_engine
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable


def record_completed_job(session, job, report, now, ports_targeted=None):
    """Provide the record completed job test fixture."""
    open_ports, document_count = report_counts(report)
    if not claim_completed_job(session, job, now, document_count):
        return False
    return increment_completed_counters(session, job, open_ports, now, ports_targeted)


class ScanStatsTest(unittest.TestCase):
    """Regression checks for scan stats test."""

    def setUp(self):
        """Create isolated state for the regression checks."""
        self.engine = create_engine("sqlite://")
        Jobs.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.session.close)
        self.now = datetime(2026, 11, 21, 10, 25, 59)

    def job(self, tool="masscan"):
        """Provide the job test fixture."""
        job = Jobs(
            uid=str(uuid.uuid4()),
            job="192.0.2.1",
            scan_tool=tool,
            active=True,
            finished=False,
            attempt_uid=str(uuid.uuid4()),
        )
        self.session.add(job)
        self.session.commit()
        return job

    def report(self):
        """Provide the report test fixture."""
        return [
            {
                "addr": "192.0.2.1",
                "ports": [
                    {"portid": "22", "protocol": "tcp", "state": {"state": "open"}},
                    {"portid": "22", "protocol": "tcp", "state": {"state": "open"}},
                    {"portid": "80", "state": {"state": "closed"}},
                    {"portid": "443", "state": {"state": "filtered"}},
                ],
            }
        ]

    def test_only_open_ip_transport_port_pairs_count(self):
        """Verify only open ip transport port pairs count."""
        report = self.report()
        self.assertEqual(count_open_ports(report * 2), 1)
        self.assertEqual(
            count_open_ports(
                report + [{"addr": "192.0.2.2", "ports": report[0]["ports"]}]
            ),
            2,
        )
        self.assertEqual(count_open_ports([{}, {"ports": 1}, None]), 0)

    def test_ingestion_counts_share_the_job_commit_and_include_only_indexable_inputs(
        self,
    ):
        """Duplicate port JSONs are export inputs even if scanning counts them once."""
        job = self.job()
        ports = self.report()[0]["ports"][:2] + [{"portid": " "}, None]
        report = [
            {"addr": "93.184.216.34", "ports": ports},
            {"addr": "192.0.2.1", "ports": ports},
        ]
        self.assertEqual(report_counts(report), (2, 2))
        self.assertTrue(record_completed_job(self.session, job, report, self.now))
        self.session.rollback()
        self.assertIsNone(self.session.get(Jobs, job.id).report_document_count)
        self.assertTrue(record_completed_job(self.session, job, report, self.now))
        self.session.commit()
        self.assertEqual(self.session.get(Jobs, job.id).report_document_count, 2)

    def test_ingestion_queue_samples_legacy_jobs_and_completed_exports(self):
        """Measure only outstanding jobs, with zero and unknown kept distinct."""
        for accepted, prepared, exported in (
            (5, 3, False),
            (0, None, False),
            (None, None, False),
            (90, None, True),
        ):
            job = self.job()
            job.active = False
            job.finished = True
            job.exported = exported
            job.report_document_count = accepted
            job.meili_documents_total = prepared
        self.session.commit()
        sample_ingestion_queue(self.session, self.now)
        sample_ingestion_queue(self.session, self.now)
        point = self.session.query(IngestionStatSample).one()
        self.assertEqual(
            (point.pending_documents, point.pending_reports, point.unknown_reports),
            (3, 3, 1),
        )

        job.exported = False
        self.session.commit()
        later = self.now + timedelta(minutes=5)
        sample_ingestion_queue(self.session, later)
        history = ingestion_series(self.session, later, "hour48")
        self.assertEqual(len(history["rows"]), 48)
        self.assertEqual(history["latest"]["pending_documents"], 93)
        self.assertIsNone(history["rows"][1]["pending_documents"])
        minute = ingestion_series(self.session, later, "minute")
        self.assertEqual(len(minute["rows"]), 12)
        self.assertEqual(minute["rows"][1]["pending_documents"], 3)

    def test_ingestion_queue_distinguishes_unmeasured_from_empty(self):
        """A legacy queue of uncounted jobs must never be presented as empty."""
        job = self.job()
        job.active = False
        job.finished = True
        self.session.commit()
        sample_ingestion_queue(self.session, self.now)
        latest = ingestion_series(self.session, self.now)["latest"]
        self.assertIsNone(latest["pending_documents"])
        self.assertEqual(latest["unknown_reports"], 1)
        job.exported = True
        self.session.commit()
        later = self.now + timedelta(minutes=5)
        sample_ingestion_queue(self.session, later)
        self.assertEqual(
            ingestion_series(self.session, later)["latest"]["pending_documents"], 0
        )

    def test_repeat_is_ignored_and_rollback_keeps_completion_atomic(self):
        """Verify repeat is ignored and rollback keeps completion atomic."""
        job = self.job()
        self.assertTrue(
            record_completed_job(self.session, job, self.report(), self.now)
        )
        self.session.rollback()
        self.assertFalse(self.session.get(Jobs, job.id).finished)
        self.assertEqual(self.session.query(ScanStatBucket).count(), 0)
        self.assertTrue(
            record_completed_job(self.session, job, self.report(), self.now)
        )
        self.session.commit()
        self.assertFalse(
            record_completed_job(self.session, job, self.report(), self.now)
        )
        row = self.session.query(ScanStatBucket).one()
        self.assertEqual(
            (row.jobs_completed, row.open_ports, row.jobs_without_target_count),
            (1, 1, 1),
        )
        self.assertEqual(row.bucket_start, self.now.replace(second=0))

    def test_empty_success_adds_job_but_no_open_port_and_upserts_same_minute(self):
        """Verify empty success adds job but no open port and upserts same minute."""
        for target_count in (0, 256):
            job = self.job()
            self.assertTrue(
                record_completed_job(self.session, job, [], self.now, target_count)
            )
            self.session.commit()
        row = self.session.query(ScanStatBucket).one()
        self.assertEqual(
            (
                row.jobs_completed,
                row.ports_targeted,
                row.open_ports,
                row.jobs_without_target_count,
            ),
            (2, 256, 0, 0),
        )

    def test_job_fallback_counts_distinct_numeric_targets_and_ports(self):
        """Nonresponders count without expanding networks or resolving names."""
        job = SimpleNamespace(
            job="192.0.2.0/24,192.0.2.1,2001:db8::/127",
            scan_ports="22,22,80-81",
        )
        self.assertEqual(job_targeted_ports(job), 258 * 3)
        for targets, ports in (
            ("example.org", "22"),
            ("192.0.2.1,example.org", "22"),
            ("192.0.2.1", None),
            ("192.0.2.1", "0"),
            ("192.0.2.1", "65536"),
            ("192.0.2.1", "80-22"),
            ("192.0.2.1", "22-23-24"),
            ("::/0", "22"),
        ):
            with self.subTest(targets=targets, ports=ports):
                self.assertIsNone(
                    job_targeted_ports(SimpleNamespace(job=targets, scan_ports=ports))
                )

    def test_agent_count_wins_including_zero_and_absence_uses_job(self):
        """Old agents get fallback; explicit counts are never overwritten."""
        for reported, expected in ((None, 512), (0, 0), (17, 17)):
            with self.subTest(reported=reported):
                job = self.job()
                job.job = "192.0.2.0/24"
                job.scan_ports = "22,443"
                record_completed_job(self.session, job, [], self.now, reported)
                self.session.commit()
                row = self.session.query(ScanStatBucket).one()
                self.assertEqual(row.ports_targeted, expected)
                self.assertEqual(row.jobs_without_target_count, 0)
                self.assertEqual(row.open_ports, 0)
                self.session.delete(row)
                self.session.commit()

    def test_minute_hour_day_grouping_and_filters(self):
        """Verify minute hour day grouping and filters."""
        for tool, offset in (("nmap", 0), ("masscan", 1), ("masscan", 24 * 60)):
            job = self.job(tool)
            record_completed_job(
                self.session,
                job,
                self.report(),
                self.now - timedelta(minutes=offset),
                10,
            )
            self.session.commit()
        for period, size, jobs in (("minute", 60, 2), ("hour", 24, 2), ("day", 30, 3)):
            result = activity_series(self.session, self.now, period)
            self.assertEqual(len(result["rows"]), size)
            self.assertEqual(result["totals"]["jobs_completed"], jobs)
        self.assertEqual(
            activity_series(self.session, self.now, "day", "nmap")["totals"][
                "jobs_completed"
            ],
            1,
        )
        self.assertEqual(
            activity_series(self.session, self.now, "bad", "bad")["period"], "hour"
        )

    def test_migration_is_repeatable_and_schema_compiles_for_mysql(self):
        """Verify migration is repeatable and schema compiles for mysql."""
        path = next(
            (Path(__file__).resolve().parents[1] / "webapp/sql_upd").glob("32_*.py")
        )
        migrate = runpy.run_path(str(path))["migrate"]
        with sqlite3.connect(":memory:") as connection:
            migrate(connection)
            migrate(connection)
            self.assertEqual(
                len(
                    connection.execute(
                        "PRAGMA table_info(scan_stat_buckets)"
                    ).fetchall()
                ),
                6,
            )
        ddl = str(
            CreateTable(ScanStatBucket.__table__).compile(dialect=mysql.dialect())
        )
        self.assertIn("PRIMARY KEY (bucket_start, scan_tool)", ddl)

    def test_mysql_upsert_increments_without_replacing_the_row(self):
        """Verify mysql upsert increments without replacing the row."""
        job = SimpleNamespace(id=1, bot_id=2, attempt_uid="attempt", scan_tool="nmap")
        session = Mock()
        session.no_autoflush = nullcontext()
        session.query.return_value.filter.return_value.update.return_value = 1
        session.get_bind.return_value.dialect.name = "mysql"
        self.assertTrue(
            record_completed_job(session, job, self.report(), self.now, 256)
        )
        sql = str(session.execute.call_args.args[0].compile(dialect=mysql.dialect()))
        self.assertIn("ON DUPLICATE KEY UPDATE", sql)
        self.assertIn("scan_stat_buckets.open_ports + VALUES(open_ports)", sql)

    def test_last_six_calendar_months_cross_year_boundary(self):
        """Verify last six calendar months cross year boundary."""
        now = datetime(2027, 1, 22, 10)
        for timestamp in (datetime(2026, 7, 31, 23, 59), datetime(2026, 8, 1), now):
            record_completed_job(self.session, self.job(), [], timestamp, 1)
            self.session.commit()
        result = activity_series(self.session, now, "month")
        self.assertEqual(
            [row["label"] for row in result["rows"]],
            ["2027-01", "2026-12", "2026-11", "2026-10", "2026-09", "2026-08"],
        )
        self.assertEqual(result["totals"]["jobs_completed"], 2)

    def test_activity_template_marks_unknown_counts_instead_of_zero(self):
        """Verify activity template marks unknown counts instead of zero."""
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        templates = Path(__file__).resolve().parents[1] / "webapp/app/templates"
        environment = Environment(
            loader=FileSystemLoader(templates), autoescape=select_autoescape()
        )
        record_completed_job(self.session, self.job(), self.report(), self.now)
        self.session.commit()
        result = activity_series(self.session, self.now)
        html = environment.get_template("scan_activity.html").render(
            activity=result, period=result["period"], stats_tab="scanning"
        )
        self.assertIn("Unknown", html)
        self.assertIn("unavailable for 1 completed job", html)
        self.assertIn("Open port observations", html)
        self.assertEqual(html.count('class="stats-chart"'), 3)
        self.assertIn('class="stats-chart-line"', html)
        self.assertIn('class="stats-chart-point"', html)
        self.assertNotIn("<rect ", html)
        self.assertNotIn(">Apply</button>", html)
        self.assertIn('name="tab" value="scanning"', html)

    def test_both_themes_keep_overview_separate_from_graphs(self):
        """Verify both themes keep overview separate from graphs."""
        from jinja2 import (
            ChoiceLoader,
            DictLoader,
            Environment,
            FileSystemLoader,
            select_autoescape,
        )

        templates = Path(__file__).resolve().parents[1] / "webapp/app/templates"
        environment = Environment(
            loader=ChoiceLoader(
                [
                    DictLoader(
                        {
                            "appbuilder/base.html": "{% block content %}{% endblock %}{% block add_tail_js %}{% endblock %}",
                            "appbuilder/general/lib.html": "{% macro panel_begin(title, name) %}{{ title }}{% endmacro %}{% macro panel_end() %}{% endmacro %}",
                        }
                    ),
                    FileSystemLoader(templates),
                ]
            ),
            autoescape=select_autoescape(),
        )
        activity = activity_series(self.session, self.now)
        sample_ingestion_queue(self.session, self.now)
        ingestion = ingestion_series(self.session, self.now, "hour48")
        stats = dict.fromkeys(
            (
                "cidr_count",
                "fqdn_count",
                "cidr_host_count",
                "total_hosts_to_scan",
                "scanned_port_count",
                "kv_scanned_host_count",
                "kv_scan_result_count",
            ),
            7,
        )
        for theme in ("stats.html", "themes/plum/stats.html"):
            template = environment.get_template(theme)
            context = dict(
                title="Stats",
                stats=stats,
                activity=activity,
                ingestion=ingestion,
                period="hour48",
                tool="all",
                baselib=SimpleNamespace(get_nonce=lambda: "nonce"),
            )
            overview = template.render(stats_tab="overview", **context)
            self.assertIn("Target CIDRs", overview)
            self.assertIn('aria-current="page">Overview', overview)
            self.assertNotIn("<svg", overview)
            graphs = template.render(stats_tab="scanning", **context)
            self.assertIn('aria-current="page">Scanning', graphs)
            self.assertNotIn("Target CIDRs", graphs)
            self.assertEqual(graphs.count("<svg"), 3)
            self.assertNotIn("nan", graphs.lower())
            ingestion_html = template.render(stats_tab="ingestion", **context)
            self.assertIn('aria-current="page">Ingestion', ingestion_html)
            self.assertIn('value="hour48" selected', ingestion_html)
            self.assertEqual(ingestion_html.count("<svg"), 2)
            self.assertIn("Port documents awaiting ingestion", ingestion_html)
            self.assertIn("form.requestSubmit()", ingestion_html)

    def test_simultaneous_submissions_count_once(self):
        """Verify simultaneous submissions count once."""
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_engine(
                "sqlite:///" + tmp + "/stats.db", connect_args={"timeout": 10}
            )
            try:
                Jobs.metadata.create_all(engine)
                sessions = sessionmaker(bind=engine)
                with sessions() as session:
                    job = Jobs(
                        uid=str(uuid.uuid4()),
                        job="192.0.2.1",
                        active=True,
                        finished=False,
                        scan_tool="masscan",
                    )
                    session.add(job)
                    session.commit()
                    job_id = job.id
                barrier = Barrier(2)

                def submit():
                    """Provide the submit test fixture."""
                    with sessions() as session:
                        job = session.get(Jobs, job_id)
                        barrier.wait(timeout=10)
                        claimed = record_completed_job(
                            session, job, self.report(), self.now
                        )
                        session.commit()
                        return claimed

                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: submit(), range(2)))
                self.assertEqual(sorted(results), [False, True])
                with sessions() as session:
                    self.assertEqual(
                        session.query(ScanStatBucket).one().jobs_completed, 1
                    )
            finally:
                engine.dispose()
