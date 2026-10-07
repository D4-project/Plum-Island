"""Report-save validation without touching search backends or real data."""

from datetime import datetime
import shlex
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.datastructures import MultiDict
from wtforms import Form

from app.models import Reports
from app.views import KVSearchView, ReportsView
from app.utils import report_query


class ReportQueryValidationTest(unittest.TestCase):
    """Use the real parser and shared library, not a duplicated test grammar."""

    def setUp(self):
        """Make backend calls fail immediately if validation accidentally uses one."""
        for target in (
            "app.views.KVrocksIndexer",
            "app.views.KVSearchView.execute_search",
        ):
            guard = patch(target, side_effect=AssertionError("No search during save"))
            guard.start()
            self.addCleanup(guard.stop)
        self.parser = KVSearchView()

    def validate(self, query):
        """Exercise the save-time helper against the production parser."""
        return report_query.validate_report_query(query, self.parser)

    def test_valid_queries_preserve_semantics(self):
        """IPv4/IPv6, quotes, repeated terms and Boolean operators remain valid."""
        queries = [
            "domain:lhc.lu or domain_requested:lcsf.lu or net:a02:6f00:c8::/48",
            "net:31.22.120.208/28 or ip:2001:db8::1",
            "tag:type:firewall AND NOT tag:vendor:example",
            "port:443 port:443 or port:80",
            'http_title:"NOT AND OR" http_headval:x-powered-by.lk:"php 8"',
            "http_server.lk:nginx since:3 debug",
            "tag:product:valid-but-not-present",
            "tag:proto:ssh tag:proto:ssh",
        ]
        for query in queries:
            with self.subTest(query=query):
                self.assertEqual(self.validate(query), query)

    def test_invalid_queries(self):
        """Reject invalid operators, types, empty values and malformed tags."""
        queries = [
            "",
            " ",
            "AND",
            "debug",
            "since:3",
            "port:443 AND",
            "AND port:443",
            "port:443 AND AND port:80",
            "port:443 OR",
            "OR port:443",
            "port:443 OR OR port:80",
            "NOT tag:proto:ssh",
            "port:443 NOT",
            "port:443 NOT NOT port:80",
            'http_title:"broken',
            "domain_requested:lcsf.lu a02:6f00:c8::/48",
            "port:",
            "port:abc",
            "port:65536",
            "port:-1",
            "port:８０",
            "ip:999.1.1.1",
            "ip:2001:xyz::1",
            "net:2001:db8::/129",
            "net:192.0.2.0/33",
            "net:192.0.2.1",
            "ip.lk:192.0.2.1",
            "banner.nonsense:foo",
            'banner:"   "',
            "http_headval:server:",
            "tag:",
            "tag:nginx",
            'tag:"product:bad tag"',
            'port:443 NOT tag:"product:bad tag"',
            "tag.lk:product:nginx",
            "port:443 since:0",
            "port:443 since:abc",
            "port:443 since:1 since:2",
        ]
        for query in queries:
            with self.subTest(query=query), self.assertRaises(ValueError):
                self.validate(query)

    def test_bare_ipv6_has_actionable_error(self):
        """Do not guess an IPv6 prefix or silently change the network."""
        with self.assertRaisesRegex(ValueError, "a02.*net:CIDR"):
            self.validate("domain:lcsf.lu a02:6f00:c8::/48")

    def test_tags_use_shared_validator_and_normalize(self):
        """Canonical normalization reaches saved terms, including negated ones."""
        query = 'tag:Product:Nginx NOT tag:tag:Vendor:Example http_title:"NOT OR"'
        with patch.object(
            report_query, "validate_tag", wraps=report_query.validate_tag
        ) as validator:
            normalized = self.validate(query)
        self.assertTrue(validator.called)
        self.assertEqual(
            shlex.split(normalized),
            ["tag:product:nginx", "NOT", "tag:vendor:example", "http_title:NOT OR"],
        )

    def test_forms_retain_invalid_input(self):
        """Both real form-field definitions attach an error without clearing data."""
        for fields in (
            ReportsView.add_form_extra_fields,
            ReportsView.edit_form_extra_fields,
        ):
            form_type = type("QueryForm", (Form,), {"query": fields["query"]})
            form = form_type(MultiDict({"query": "a02:6f00:c8::/48"}))
            self.assertFalse(form.validate())
            self.assertIn("a02", form.query.errors[0])
            self.assertEqual(form.query.data, "a02:6f00:c8::/48")

    def test_add_edit_persistence_and_failed_edit(self):
        """Save valid data in disposable SQL; invalid forms leave saved data intact."""
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        Reports.__table__.create(engine)
        view = ReportsView()
        with sessionmaker(bind=engine)() as session:
            report = Reports(
                name="test",
                query="port:443",
                emails="test@example.org",
                active=False,
                schedule_type="monthly",
                schedule_day=1,
                schedule_hour=8,
            )
            view.pre_add(report)
            session.add(report)
            session.commit()
            saved_query, saved_schedule = report.query, report.next_run_at
            form_type = type(
                "QueryForm",
                (Form,),
                {"query": ReportsView.edit_form_extra_fields["query"]},
            )
            form = form_type(MultiDict({"query": "port:bad"}))
            if form.validate():
                form.populate_obj(report)
                view.pre_update(report)
                session.commit()
            session.expire_all()
            self.assertEqual(report.query, saved_query)
            self.assertEqual(report.next_run_at, saved_schedule)
            report.query = "net:a02:6f00:c8::/48"
            view.pre_update(report)
            session.commit()
            session.expire_all()
            self.assertEqual(report.query, "net:a02:6f00:c8::/48")

    def test_hooks_reject_before_changing_schedule(self):
        """Bypassing the form still cannot normalize/schedule an invalid report."""
        for hook in (ReportsView().pre_add, ReportsView().pre_update):
            report = Reports(
                name=" untouched ", query="port:bad", next_run_at=datetime(2026, 1, 1)
            )
            with self.assertRaises(ValueError):
                hook(report)
            self.assertEqual(report.name, " untouched ")
            self.assertEqual(report.next_run_at, datetime(2026, 1, 1))


if __name__ == "__main__":
    unittest.main()
