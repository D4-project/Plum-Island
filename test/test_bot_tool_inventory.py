"""Inventory announcements and legacy rows use the same Bot Status semantics."""

import json
import runpy
import sqlite3
import tempfile
import uuid
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from test.test_scanprofile_api import ProfileApiFixture
from unittest.mock import patch

from app import apis
from app.models import (
    ApiKeys,
    Bots,
    Jobs,
    ScanProfileCycles,
    ScanProfiles,
    ScanStatBucket,
)
from werkzeug.security import generate_password_hash


class BotInventoryTest(ProfileApiFixture):
    """Regression checks for bot inventory test."""

    def configure_catalogue(self):
        """Provide the configure catalogue test fixture."""
        self.builder.add_api(apis.Api)

    def test_filtered_job_uses_existing_agent_contract(self):
        """Current filtered revision dispatches as an ordinary scanner job."""
        key = "fedcba9876543210" + "2" * 64
        self.db.session.add(
            ApiKeys(
                keyidx=key[:16],
                key=generate_password_hash(key),
                description="filtered dispatch",
            )
        )
        profile = ScanProfiles(
            name="Filtered",
            search_query="tag:vendor:nginx",
            filter_enabled=True,
            filter_revision=2,
            apply_to_all=False,
        )
        current = ScanProfileCycles(
            scanprofile=profile,
            status="running",
            filter_revision=2,
            preparation_status="queued",
        )
        stale = ScanProfileCycles(
            scanprofile=profile,
            status="finished",
            filter_revision=1,
            preparation_status="queued",
        )
        self.db.session.add_all(
            [
                Jobs(
                    uid=str(uuid.uuid4()),
                    job="203.0.113.1",
                    priority=4,
                    scanprofile=profile,
                    scanprofile_cycle=stale,
                    scan_ports="80",
                    scan_tool="nmap",
                ),
                Jobs(
                    uid=str(uuid.uuid4()),
                    job="www.example.org",
                    priority=3,
                    scanprofile=profile,
                    scanprofile_cycle=current,
                    scan_ports="80,443",
                    scan_nses="banner.nse",
                    scan_tool="nmap",
                ),
            ]
        )
        self.db.session.commit()
        payload = {
            "UID": str(uuid.uuid4()),
            "AGENT_KEY": key,
            "EXT_IP": "93.184.216.34",
            "DEVICE_MODEL": "fixture",
            "SYSTEM_VERSION": "fixture",
            "AGENT_VERSION": "fixture",
        }
        self.enterContext(patch.object(apis, "get_country", return_value="LU"))
        self.assertEqual(
            self.client.post("/bot_api/beacon", json=payload).status_code, 200
        )
        response = self.client.post("/bot_api/getjob", json=payload)
        self.assertEqual(response.status_code, 200)
        message = response.json["message"]
        self.assertEqual(message["job"], "www.example.org")
        self.assertEqual(message["scan_ports"], ["80", "443"])
        self.assertEqual(message["scan_tool"], "nmap")
        self.assertIn("nmap_nse", message)

    def test_beacon_and_poll(self):
        """Verify beacon and poll."""
        key = "0123456789abcdef" + "1" * 64
        self.db.session.add(
            ApiKeys(
                keyidx=key[:16],
                key=generate_password_hash(key),
                description="test inventory",
            )
        )
        self.db.session.commit()
        payload = {
            "UID": str(uuid.uuid4()),
            "AGENT_KEY": key,
            "EXT_IP": "93.184.216.34",
            "DEVICE_MODEL": "fixture",
            "SYSTEM_VERSION": "fixture",
            "AGENT_VERSION": "fixture",
        }
        self.enterContext(patch.object(apis, "get_country", return_value="LU"))

        def announce(**changes):
            """Provide the announce test fixture."""
            return self.client.post("/bot_api/beacon", json=dict(payload, **changes))

        protocol = self.client.get("/bot_api/protocol")
        self.assertEqual(protocol.status_code, 200)
        self.assertTrue(protocol.json["tool_inventory"])
        self.assertEqual(self.db.session.query(Bots).count(), 0)
        self.assertEqual(announce().status_code, 200)
        bot = self.db.session.query(Bots).filter_by(uid=payload["UID"]).one()
        self.assertEqual((bot.has_nmap, bot.has_masscan), (True, False))
        self.assertFalse(bot.supports_job_attempts)
        self.assertEqual(announce(capabilities=["masscan"]).status_code, 200)
        self.db.session.refresh(bot)
        self.assertEqual((bot.has_nmap, bot.has_masscan), (False, True))
        self.assertTrue(bot.supports_job_attempts)
        inventory = str(bot.reported_tools_html())
        self.assertIn("Masscan available", inventory)
        self.assertIn("Nmap unavailable", inventory)
        self.assertLess(inventory.index(">Scanner<"), inventory.index(">Banner<"))
        self.assertIn("Masscan Scanner IPv4 available", inventory)
        self.assertIn("Masscan Scanner IPv6 unavailable", inventory)

        def poll_empty_queue():
            """Provide the poll empty queue test fixture."""
            contact_time = bot.last_seen + timedelta(seconds=30)
            bot.running = True
            self.db.session.commit()
            with patch.object(apis, "utcnow_naive", return_value=contact_time):
                response = self.client.post("/bot_api/getjob", json=payload)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["message"]["job"], "")
            self.db.session.refresh(bot)
            self.assertEqual(bot.last_seen, contact_time)
            self.assertTrue(bot.running)

        poll_empty_queue()
        self.assertFalse(bot.has_nmap)
        self.assertEqual(
            announce(capabilities=["masscan"], masscan_ip="192.0.2.10").status_code, 200
        )
        self.db.session.refresh(bot)
        self.assertEqual(bot.masscan_ip, "192.0.2.10")
        self.assertEqual(
            announce(capabilities=["masscan"], masscan_ip="127.0.0.1").status_code, 400
        )
        self.assertEqual(announce(capabilities=["masscan"]).status_code, 200)
        self.db.session.refresh(bot)
        self.assertIsNone(bot.masscan_ip)
        self.assertEqual(announce(capabilities=["unknown"]).status_code, 400)
        for tools in (["nmap", "masscan"], []):
            with self.subTest(tools=tools):
                self.assertEqual(announce(capabilities=tools).status_code, 200)
                self.db.session.refresh(bot)
                self.assertEqual(
                    (bot.has_nmap, bot.has_masscan), (bool(tools), bool(tools))
                )
                if not tools:
                    poll_empty_queue()
        self.assertEqual(announce().status_code, 200)
        self.db.session.refresh(bot)
        self.assertEqual((bot.has_nmap, bot.has_masscan), (True, False))

    def test_migration_preserves_old_bot_and_can_be_replayed(self):
        """Verify migration preserves old bot and can be replayed."""
        directory = Path(__file__).resolve().parents[1] / "webapp/sql_upd"
        migrate = runpy.run_path(str(next(directory.glob("27_*.py"))))["migrate"]
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute("CREATE TABLE bots (id INTEGER PRIMARY KEY, uid TEXT)")
            conn.execute("INSERT INTO bots (uid) VALUES ('legacy')")
            migrate(conn)
            migrate(conn)
            self.assertEqual(
                conn.execute("SELECT uid, has_nmap, has_masscan FROM bots").fetchone(),
                ("legacy", 1, 0),
            )
            source_migration = runpy.run_path(str(next(directory.glob("31_*.py"))))[
                "migrate"
            ]
            source_migration(conn)
            source_migration(conn)
            self.assertIsNone(conn.execute("SELECT masscan_ip FROM bots").fetchone()[0])

    def test_dispatcher_skips_incompatible_higher_priority_job(self):
        """Verify dispatcher skips incompatible higher priority job."""
        key = "fedcba9876543210" + "2" * 64
        self.db.session.add(
            ApiKeys(
                keyidx=key[:16],
                key=generate_password_hash(key),
                description="dispatcher test",
            )
        )
        self.db.session.add_all(
            [
                Jobs(
                    uid=str(uuid.uuid4()),
                    job="192.0.2.1",
                    priority=4,
                    scan_ports="443",
                    scan_tool="masscan",
                    scan_family="ipv4",
                    detect_protocol=True,
                ),
                Jobs(
                    uid=str(uuid.uuid4()),
                    job="192.0.2.2",
                    priority=3,
                    scan_ports="22",
                    scan_tool="nmap",
                ),
            ]
        )
        self.db.session.commit()
        base = {
            "AGENT_KEY": key,
            "EXT_IP": "93.184.216.34",
            "DEVICE_MODEL": "fixture",
            "SYSTEM_VERSION": "fixture",
            "AGENT_VERSION": "fixture",
        }
        self.enterContext(patch.object(apis, "get_country", return_value="LU"))

        legacy = dict(base, UID=str(uuid.uuid4()))
        self.assertEqual(
            self.client.post("/bot_api/beacon", json=legacy).status_code, 200
        )
        response = self.client.post("/bot_api/getjob", json=legacy)
        self.assertEqual(response.status_code, 200)
        message = response.json["message"]
        self.assertEqual((message["scan_tool"], message["job"]), ("nmap", "192.0.2.2"))
        self.assertEqual(message["nmap_ports"], ["22"])
        self.assertIsNone(message["attempt_uid"])
        self.assertIn("nmap_nse", message)

        no_banner = dict(base, UID=str(uuid.uuid4()), capabilities=["masscan"])
        self.assertEqual(
            self.client.post("/bot_api/beacon", json=no_banner).status_code, 200
        )
        response = self.client.post("/bot_api/getjob", json=no_banner)
        self.assertEqual(response.json["message"]["job"], "")
        queued_banner = self.db.session.query(Jobs).filter_by(scan_tool="masscan").one()
        self.assertIn("No Masscan agent", str(queued_banner.banner_status_html()))

        masscan = dict(
            base,
            UID=str(uuid.uuid4()),
            capabilities=["masscan"],
            masscan_ip="192.0.2.10",
        )
        self.assertEqual(
            self.client.post("/bot_api/beacon", json=masscan).status_code, 200
        )
        response = self.client.post("/bot_api/getjob", json=masscan)
        reported_bot = self.db.session.query(Bots).filter_by(uid=masscan["UID"]).one()
        self.assertIn(
            "Masscan Banner IPv4 available (192.0.2.10)",
            str(reported_bot.reported_tools_html()),
        )
        self.assertEqual(response.status_code, 200)
        message = response.json["message"]
        self.assertEqual(
            (message["scan_tool"], message["job"]), ("masscan", "192.0.2.1")
        )
        self.assertEqual(message["scan_ports"], ["443"])
        self.assertTrue(message["detect_protocol"])
        self.assertNotIn("nmap_nse", message)
        first_attempt = message["attempt_uid"]
        self.assertTrue(first_attempt)

        stale_result = dict(
            masscan,
            JOB_UID=message["job_uid"],
            ATTEMPT_UID=str(uuid.uuid4()),
            RESULT="[]",
        )
        self.assertEqual(
            self.client.post("/bot_api/sndjob", json=stale_result).status_code,
            409,
        )
        release = {
            "UID": masscan["UID"],
            "AGENT_KEY": key,
            "JOB_UID": message["job_uid"],
            "ATTEMPT_UID": first_attempt,
        }
        self.assertEqual(
            self.client.post("/bot_api/releasejob", json=release).status_code,
            200,
        )
        message = self.client.post("/bot_api/getjob", json=masscan).json["message"]
        self.assertNotEqual(message["attempt_uid"], first_attempt)
        stale_result["ATTEMPT_UID"] = first_attempt
        self.assertEqual(
            self.client.post("/bot_api/sndjob", json=stale_result).status_code,
            409,
        )
        current = self.db.session.query(Jobs).filter_by(uid=message["job_uid"]).one()
        report = [
            {
                "addr": "192.0.2.1",
                "endtime": "100",
                "ports": [
                    {
                        "portid": "443",
                        "protocol": "tcp",
                        "state": {"state": "open"},
                        "scripts": [
                            {
                                "id": "masscan-detection",
                                "service": "ssl",
                                "output": "TLS response",
                            }
                        ],
                    }
                ],
            }
        ]
        immediate_result = dict(
            masscan,
            JOB_UID=message["job_uid"],
            ATTEMPT_UID=message["attempt_uid"],
            RESULT=json.dumps(report),
        )
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, message["job_uid"][0]).mkdir()
            with patch.dict(self.app.config, JSON_FOLDER=directory), patch.object(
                apis, "utcnow_naive", return_value=current.job_start
            ):
                response = self.client.post("/bot_api/sndjob", json=immediate_result)
            saved = Path(directory, message["job_uid"][0], message["job_uid"] + ".json")
            self.assertEqual(json.loads(saved.read_text()), report)
        self.assertEqual(response.status_code, 200)
        self.db.session.refresh(current)
        self.assertTrue(current.finished)
        counters = self.db.session.query(ScanStatBucket).one()
        self.assertEqual((counters.jobs_completed, counters.open_ports), (1, 1))
        self.assertEqual(counters.jobs_without_target_count, 0)
        self.assertEqual(counters.ports_targeted, 1)
        # An acknowledged resend must never count again or need the source file.
        self.assertEqual(
            self.client.post("/bot_api/sndjob", json=immediate_result).status_code, 200
        )
        self.db.session.refresh(counters)
        self.assertEqual(counters.jobs_completed, 1)

        empty = Jobs(
            uid=str(uuid.uuid4()),
            job="192.0.2.3",
            priority=4,
            scan_ports="443",
            scan_tool="masscan",
            scan_family="ipv4",
        )
        self.db.session.add(empty)
        self.db.session.commit()
        second = self.client.post("/bot_api/getjob", json=masscan).json["message"]
        self.assertEqual(second["job_uid"], empty.uid)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, empty.uid[0]).mkdir()
            with patch.dict(self.app.config, JSON_FOLDER=directory), patch.object(
                apis, "utcnow_naive", return_value=empty.job_start
            ):
                response = self.client.post(
                    "/bot_api/sndjob",
                    json=dict(
                        masscan,
                        JOB_UID=empty.uid,
                        ATTEMPT_UID=second["attempt_uid"],
                        RESULT="[]",
                        PORTS_TARGETED=256,
                    ),
                )
            self.assertEqual(response.status_code, 200)
            saved = Path(directory, empty.uid[0], empty.uid + ".json")
            self.assertEqual(json.loads(saved.read_text()), [])
        self.db.session.refresh(empty)
        self.assertTrue(empty.finished)
        rows = self.db.session.query(ScanStatBucket).all()
        self.assertEqual(sum(row.jobs_completed for row in rows), 2)
        self.assertEqual(sum(row.open_ports for row in rows), 1)
        self.assertEqual(sum(row.ports_targeted for row in rows), 257)
