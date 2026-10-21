"""Resolved CSV formatting, bounded lookups and protected asynchronous exports."""

import csv
import io
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import dns.resolver
from itsdangerous import URLSafeTimedSerializer
import requests

from app import app, appbuilder
from app import views
from app.utils import resolved_export as resolved
from tools.initial_setup import load_role_definition, normalize_permission_label

# pylint: disable=protected-access,missing-function-docstring

ROOT = Path(__file__).resolve().parents[1]
IP = "192.0.2.10"
V6 = "2001:db8::1"
TIME_RANGE = {"from_ts": 100, "to_ts": 300}


def results_fixture():
    return {
        "status": True,
        "time_range": TIME_RANGE,
        "results": {V6: ["v6"], IP: ["old", "new"], "192.0.2.2": ["other"]},
        "timestamps": {IP: {"max_seen": 1789396987}, V6: {"max_seen": None}},
    }


class ResolvedCsvTest(unittest.TestCase):
    """No DNS, HTTP or index writes; use fixed records for both IP families."""

    @unittest.skipUnless(shutil.which("node"), "Node.js required for UI test")
    def test_export_button_and_shared_modal_configuration(self):
        subprocess.run(
            [shutil.which("node"), str(ROOT / "test/search_resolved_export_ui.js")],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_csv_columns_last_seen_dedup_and_csv_escaping(self):
        output, warnings, progress = io.StringIO(newline=""), [], []
        loader = Mock(
            return_value={
                "body": {"hostnames": [{"type": "PTR", "name": "ptr.example.org"}]}
            }
        )
        with patch.object(
            resolved, "lookup_pdns", return_value=["one.example.org", "two.example.org"]
        ) as pdns:
            resolved.write_resolved_csv(
                output,
                results_fixture(),
                {"PASSIVE_USER": "test", "PASSIVE_PWD": "secret"},
                progress.append,
                warnings.append,
                document_loader=loader,
            )
        for call in pdns.call_args_list:
            self.assertEqual(call.args[3], TIME_RANGE)
        rows = list(csv.reader(io.StringIO(output.getvalue())))
        self.assertEqual(rows[0], ["ip", "last seen", "ptr", "pdns"])
        self.assertEqual([row[0] for row in rows[1:]], ["192.0.2.2", IP, V6])
        self.assertEqual(
            rows[2],
            [
                IP,
                "2026-09-14 14:43:07",
                "ptr.example.org",
                "one.example.org,two.example.org",
            ],
        )
        self.assertEqual(rows[3][1], "")
        self.assertEqual(progress, [1, 2, 3])
        self.assertEqual(warnings, [])
        self.assertIn('"one.example.org,two.example.org"', output.getvalue())

    def test_spreadsheet_injection_and_quoting(self):
        for value in (
            "=1+1",
            "+cmd",
            "-cmd",
            "@SUM(1)",
            "\tname",
            "\rname",
            "\nname",
            "  =1",
        ):
            self.assertEqual(resolved.csv_cell(value), "'" + value)
        output = io.StringIO(newline="")
        value = 'hello,"quoted"\nworld'
        csv.writer(output).writerow([resolved.csv_cell(value)])
        self.assertEqual(next(csv.reader(io.StringIO(output.getvalue()))), [value])
        self.assertEqual(resolved.last_seen_text(float("inf")), "")
        self.assertEqual(resolved.last_seen_text(0), "1970-01-01 00:00:00")

    def test_ptr_only_from_matching_scan_documents_without_dns(self):
        documents = {
            "old": {
                "body": {
                    "hostnames": [
                        {"type": "PTR", "name": "Old.Example.org."},
                        {"type": "user", "name": "requested.example.org"},
                        {"name": "generic.example.org"},
                        "invalid",
                    ]
                }
            },
            "new": {
                "body": {
                    "hostnames": [
                        {"type": "ptr", "hostname": "new.example.org"},
                        {"type": "PTR", "name": "old.example.org"},
                        {"type": "PTR", "name": IP},
                    ]
                }
            },
            "v6": {"body": {"hostnames": [{"type": "PTR", "name": "v6.example.org"}]}},
            "other": None,
            "outside-search": {
                "body": {"hostnames": [{"type": "PTR", "name": "excluded.example.org"}]}
            },
        }
        loader = Mock(side_effect=documents.__getitem__)
        output = io.StringIO(newline="")
        with patch.object(dns.resolver, "Resolver") as resolver, patch.object(
            resolved, "lookup_pdns"
        ) as pdns:
            resolved.write_resolved_csv(
                output, results_fixture(), {}, Mock(), Mock(), document_loader=loader
            )
        resolver.assert_not_called()
        pdns.assert_not_called()
        self.assertEqual(
            {call.args[0] for call in loader.call_args_list},
            {"old", "new", "v6", "other"},
        )
        rows = list(csv.reader(io.StringIO(output.getvalue())))
        self.assertEqual(rows[1][2], "")
        self.assertEqual(rows[2][2], "new.example.org,old.example.org")
        self.assertEqual(rows[3][2], "v6.example.org")

    def test_pdns_orientation_families_and_unrelated_records(self):
        for ip, kind in ((IP, "A"), (V6, "AAAA")):
            records = [
                {"rrtype": kind, "rrname": "Host.Example.org.", "rdata": ip},
                {"rrtype": kind, "rrname": ip, "rdata": "host.example.org"},
                {"rrtype": "TXT", "rrname": "bad.example.org", "rdata": ip},
                {
                    "rrtype": kind,
                    "rrname": "unrelated.example.org",
                    "rdata": "192.0.2.200",
                },
                {"rrtype": kind, "rrname": "=cmd", "rdata": ip},
            ]
            with patch.object(resolved.requests, "get") as get:
                response = get.return_value.__enter__.return_value
                response.status_code = 200
                response.iter_content.return_value = [
                    "\n".join(
                        json.dumps(dict(r, time_first=100, time_last=300))
                        for r in records
                    ).encode()
                ]
                self.assertEqual(
                    resolved.lookup_pdns(ip, "user", "password", TIME_RANGE),
                    ["host.example.org"],
                )
                kwargs = get.call_args.kwargs
                self.assertFalse(kwargs["allow_redirects"])
                self.assertEqual(kwargs["headers"]["dribble-disable-active-query"], "1")
        self.assertIsNone(resolved.pdns_hostname([], ipaddress.ip_address(IP)))

    def test_pdns_failures_and_size_limit_do_not_return_partial_data(self):
        with patch.object(resolved.requests, "get") as get:
            get.side_effect = requests.Timeout("private upstream details")
            with self.assertRaisesRegex(LookupError, "timed out"):
                resolved.lookup_pdns(IP, "user", "secret", TIME_RANGE)
            get.side_effect = None
            response = get.return_value.__enter__.return_value
            for status, body in (
                (302, b""),
                (500, b""),
                (200, b"not json"),
                (200, b"x" * 21),
            ):
                response.status_code = status
                response.iter_content.return_value = [body]
                with patch.object(resolved, "PDNS_MAX_BYTES", 20), self.assertRaises(
                    LookupError
                ):
                    resolved.lookup_pdns(IP, "user", "secret", TIME_RANGE)

    def test_pdns_search_time_overlap_inclusive_and_invalid_dates(self):
        intervals = [
            ("before", 1, 99),
            ("after", 301, 400),
            ("inside", 150, 200),
            ("spanning", 50, 400),
            ("start", 50, 100),
            ("end", 300, 400),
            ("unknown", None, None),
            ("missing-first", None, 200),
            ("reversed", 200, 100),
            ("invalid", "bad", 200),
            ("nan", "nan", 200),
            ("infinite", 100, "inf"),
            ("boolean", True, 200),
            ("negative", -100, 200),
        ]
        for ip, kind in ((IP, "A"), (V6, "AAAA")):
            records = [
                {
                    "rrname": ip,
                    "rdata": name + ".example.org",
                    "rrtype": kind,
                    "time_first": first,
                    "time_last": last,
                }
                for name, first, last in intervals
            ]
            with patch.object(resolved.requests, "get") as get:
                response = get.return_value.__enter__.return_value
                response.status_code = 200
                response.iter_content.return_value = [
                    "\n".join(json.dumps(r) for r in records).encode()
                ]
                self.assertEqual(
                    resolved.lookup_pdns(ip, "user", "secret", TIME_RANGE),
                    [
                        "end.example.org",
                        "inside.example.org",
                        "spanning.example.org",
                        "start.example.org",
                    ],
                )
        self.assertTrue(
            resolved.pdns_in_time_range(
                {"time_first": "100", "time_last": "300"}, TIME_RANGE
            )
        )
        self.assertFalse(resolved.pdns_in_time_range([], TIME_RANGE))

    def test_missing_credentials_and_missing_documents_preserve_rows(self):
        for config in ({}, {"PASSIVE_USER": "user"}):
            warnings, progress = [], []
            output = io.StringIO(newline="")
            with patch.object(resolved, "lookup_pdns") as pdns:
                resolved.write_resolved_csv(
                    output,
                    results_fixture(),
                    config,
                    progress.append,
                    warnings.append,
                    document_loader=Mock(return_value=None),
                )
            pdns.assert_not_called()
            rows = list(csv.reader(io.StringIO(output.getvalue())))
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(row[2:] == ["", ""] for row in rows[1:]))
            self.assertEqual(len(warnings), 1)


class ResolvedExportRoutesTest(unittest.TestCase):
    """Exercise real FAB-decorated endpoints with disposable files and fake workers."""

    def setUp(self):
        self.client = app.test_client()
        self.owner = SimpleNamespace(id=71)
        self.states = {}
        for target, replacement in (
            ("current_user", self.owner),
            ("EXPORT_JOB_STATES", self.states),
        ):
            guard = patch.object(views, target, replacement)
            guard.start()
            self.addCleanup(guard.stop)
        self.slots = Mock()
        self.slots.acquire.return_value = True
        guard = patch.object(views, "RESOLVED_EXPORT_SLOTS", self.slots)
        guard.start()
        self.addCleanup(guard.stop)
        with self.client.session_transaction() as session:
            session["csrf_token"] = "resolved-csrf"
        secret = app.config.get("WTF_CSRF_SECRET_KEY") or app.secret_key
        self.headers = {
            "X-CSRFToken": URLSafeTimedSerializer(secret, salt="wtf-csrf-token").dumps(
                "resolved-csrf"
            )
        }
        self.payload = {"q": "(port:80 OR port:443)", "from_ts": 100, "to_ts": 300}

    def start(self, payload=None, headers=None):
        return self.client.post(
            "/kvsearchview/export_resolved_start",
            json=self.payload if payload is None else payload,
            headers=self.headers if headers is None else headers,
        )

    def test_role_permissions_success_and_single_owner_job(self):
        _, labels = load_role_definition(ROOT / "webapp/security_roles/read_only.yaml")
        permissions = {normalize_permission_label(label) for label in labels}
        with patch.object(
            appbuilder.sm, "has_access", side_effect=lambda p, v: (p, v) in permissions
        ), patch.object(views.threading, "Thread") as thread:
            response = self.start()
            self.assertEqual(response.status_code, 200)
            job = self.states[response.json["job_id"]]
            self.assertEqual(job["owner_user_id"], 71)
            self.assertEqual(job["export_type"], "resolved_csv")
            self.assertEqual((job["from_ts"], job["to_ts"]), (100, 300))
            thread.return_value.start.assert_called_once()
            self.assertEqual(self.start().status_code, 409)
            response = self.client.get(
                "/kvsearchview/export_resolved_status",
                query_string={"job_id": job["job_id"]},
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json["download_ready"])

    def test_denied_csrf_invalid_and_busy(self):
        with patch.object(
            appbuilder.sm, "has_access", return_value=False
        ), patch.object(views.threading, "Thread") as thread:
            for suffix in ("start", "status", "download"):
                call = self.client.post if suffix == "start" else self.client.get
                response = call(f"/kvsearchview/export_resolved_{suffix}")
                self.assertIn(response.status_code, (302, 403))
            thread.assert_not_called()
        with patch.object(appbuilder.sm, "has_access", return_value=True), patch.object(
            views.threading, "Thread"
        ) as thread:
            self.assertEqual(self.start(headers={}).status_code, 400)
            for payload in (
                [],
                {"q": 10},
                {"q": "((port:80))"},
                {"q": "port:80", "from_ts": 300, "to_ts": 100},
            ):
                self.assertEqual(self.start(payload).status_code, 400)
            self.slots.acquire.return_value = False
            self.assertEqual(self.start().status_code, 503)
            thread.assert_not_called()

    def test_document_read_failure_aborts_and_cleans_partial_csv(self):
        with tempfile.TemporaryDirectory(
            prefix="resolved-test-"
        ) as folder, patch.object(
            appbuilder.sm, "has_access", return_value=True
        ), patch.object(
            views.threading, "Thread"
        ):
            job_id = self.start().json["job_id"]
            with patch.object(
                views.KVSearchView, "execute_search", return_value=results_fixture()
            ), patch.object(
                views.KVSearchView, "_get_export_jobs_folder", return_value=folder
            ), patch.object(
                views.client, "index"
            ), patch.object(
                views.KVSearchView,
                "load_meili_document",
                side_effect=RuntimeError("private backend details"),
            ), patch.dict(
                app.config, PASSIVE_USER="", PASSIVE_PWD=""
            ):
                views.KVSearchView._run_resolved_export_job(job_id)
            self.assertEqual(self.states[job_id]["status"], "error")
            self.assertNotIn("private", self.states[job_id]["error"])
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.slots.release.assert_called_once()

    def test_worker_download_ownership_types_and_failed_search(self):
        with tempfile.TemporaryDirectory(
            prefix="resolved-test-"
        ) as folder, patch.object(
            appbuilder.sm, "has_access", return_value=True
        ), patch.object(
            views.threading, "Thread"
        ):
            job_id = self.start().json["job_id"]
            with patch.object(
                views.KVSearchView, "execute_search", return_value=results_fixture()
            ) as search, patch.object(
                views.KVSearchView, "_get_export_jobs_folder", return_value=folder
            ), patch.object(
                views.client, "index"
            ) as index, patch.object(
                views.KVSearchView,
                "load_meili_document",
                side_effect=lambda _index, uid: (
                    (None, "document_not_found", "ignored")
                    if uid == "other"
                    else (
                        {
                            "body": {
                                "hostnames": [
                                    {"type": "PTR", "name": "ptr.example.org"}
                                ]
                            }
                        },
                        None,
                        None,
                    )
                ),
            ) as loader, patch.object(
                dns.resolver, "Resolver"
            ) as resolver, patch.dict(
                app.config, PASSIVE_USER="", PASSIVE_PWD=""
            ):
                views.KVSearchView._run_resolved_export_job(job_id)
            search.assert_called_once_with(self.payload["q"], 100, 300)
            index.assert_called_once_with("plum")
            self.assertEqual(
                {call.args[1] for call in loader.call_args_list},
                {"old", "new", "v6", "other"},
            )
            resolver.assert_not_called()
            self.assertEqual(self.states[job_id]["processed_uids"], 3)
            self.assertEqual(self.states[job_id]["warning_count"], 2)
            self.slots.release.assert_called_once()
            response = self.client.get(
                "/kvsearchview/export_resolved_download",
                query_string={"job_id": job_id},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                len(list(csv.reader(io.StringIO(response.data.decode())))), 4
            )
            rows = list(csv.reader(io.StringIO(response.data.decode())))
            self.assertEqual(rows[1][2], "")
            self.assertEqual(rows[2][2], "ptr.example.org")
            self.assertIn("resolved_ips.csv", response.headers["Content-Disposition"])
            response.close()
            for suffix in ("status", "download"):
                self.owner.id = 72
                self.assertEqual(
                    self.client.get(
                        f"/kvsearchview/export_resolved_{suffix}",
                        query_string={"job_id": job_id},
                    ).status_code,
                    403,
                )
                self.owner.id = 71
                self.states[job_id]["export_type"] = "full_json"
                self.assertEqual(
                    self.client.get(
                        f"/kvsearchview/export_resolved_{suffix}",
                        query_string={"job_id": job_id},
                    ).status_code,
                    409,
                )
                self.states[job_id]["export_type"] = "resolved_csv"
            with patch.object(
                views.KVSearchView, "execute_search", side_effect=RuntimeError("secret")
            ):
                views.KVSearchView._run_resolved_export_job(job_id)
            self.assertEqual(self.states[job_id]["status"], "error")
            self.assertNotIn("secret", self.states[job_id]["error"])


if __name__ == "__main__":
    unittest.main()
