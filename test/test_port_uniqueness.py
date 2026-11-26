"""Regression coverage for port catalogue upgrades, GUI and REST writes."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import runpy
import sqlite3
import tempfile
from test.test_scanprofile_api import ProfileApiFixture
from threading import Barrier
import unittest
from unittest.mock import patch

from flask import g
from flask_appbuilder.models.sqla.interface import SQLAInterface
from sqlalchemy.exc import IntegrityError
from app import apis, views
from app.models import Ports, Protos, ScanProfiles
from tools import initial_setup, update_sql

MIGRATE = runpy.run_path(str(next(update_sql.MIGRATIONS.glob("26_*.py"))))["migrate"]


class PortMigrationTest(unittest.TestCase):
    """Keep foreign keys and profile membership intact while merging catalogues."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE ports(id INTEGER PRIMARY KEY, value INTEGER, name TEXT,
                               proto_id INTEGER, proto_to_port TEXT UNIQUE NOT NULL);
            CREATE TABLE scanprofiles(id INTEGER PRIMARY KEY);
            CREATE TABLE scanprofiles_ports_assoc(scanprofile_id REFERENCES scanprofiles,
                                                  port_id REFERENCES ports);
            INSERT INTO ports VALUES (1,80,'web',1,'TCP:80'), (2,80,'other',1,'80:1'),
                (3,80,'third',1,'~3'), (4,80,'udp',2,'81:1'), (5,81,'tcp',1,'80:2');
            INSERT INTO scanprofiles VALUES (10),(11);
            INSERT INTO scanprofiles_ports_assoc VALUES
                (10,1),(10,2),(10,2),(10,4),(11,3),(11,5);
        """)

    def test_upgrade_and_rerun(self):
        """Merge overlapping and disjoint assignments, including swapped legacy keys."""
        for _ in range(2):
            with self.conn:
                self.conn.execute("BEGIN IMMEDIATE")
                MIGRATE(self.conn)
        self.assertEqual(
            self.conn.execute(
                "SELECT id,name,proto_to_port FROM ports ORDER BY id"
            ).fetchall(),
            [(1, "web", "80:1"), (4, "udp", "80:2"), (5, "tcp", "81:1")],
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT * FROM scanprofiles_ports_assoc ORDER BY 1,2"
            ).fetchall(),
            [(10, 1), (10, 4), (11, 1), (11, 5)],
        )
        self.assertEqual(self.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO ports VALUES(9,80,'duplicate',1,'different')"
            )

    def test_failed_upgrade_preserves_original_catalogue(self):
        """An incompatible existing index aborts the entire updater transaction."""
        self.conn.execute("CREATE INDEX uq_ports_proto_value ON ports(value)")
        before = list(self.conn.iterdump())
        with self.assertRaisesRegex(ValueError, "incompatible"), self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            MIGRATE(self.conn)
        self.assertEqual(list(self.conn.iterdump()), before)


class PortHttpTest(ProfileApiFixture):
    """Use real admin requests, distinct protocol records and an on-disk test DB."""

    def database_uri(self):
        # pylint: disable-next=consider-using-with
        folder = self.enterContext(tempfile.TemporaryDirectory())
        return f"sqlite:///{Path(folder) / 'test.db'}"

    def configure_catalogue(self):
        super().configure_catalogue()
        self.builder.add_api(apis.PortsApi)
        self.enterContext(patch.object(views, "db", self.db))
        self.enterContext(
            patch.object(
                views.PortsView, "datamodel", SQLAInterface(Ports, self.db.session)
            )
        )
        self.builder.add_view_no_menu(views.PortsView)
        self.enterContext(
            patch.object(
                views.ScanprofilesView,
                "datamodel",
                SQLAInterface(ScanProfiles, self.db.session),
            )
        )
        self.builder.add_view_no_menu(views.ScanprofilesView)

    def setUp(self):
        super().setUp()
        self.tcp = Protos(value="TCP", name="TCP")
        self.db.session.add_all([self.tcp, Protos(value="UDP", name="UDP")])
        self.db.session.commit()
        self.ports_url = "/api/v1/ports/"

    def create_port(self, proto, value):
        """Create a port through the JSON API."""
        return self.client.post(
            self.ports_url,
            headers=self.admin,
            json={"proto": proto, "value": value, "name": "web"},
        )

    def test_rest_gui_and_profile_links(self):
        """The form and API share duplicate handling and keep protocol siblings."""
        tcp = self.create_port("tcp", 80).json["result"]["id"]
        udp = self.create_port("UDP", 80).json["result"]["id"]
        port_url = self.ports_url + str(udp)
        self.assertEqual(self.create_port("TCP", 80).status_code, 400)
        failed = self.client.put(
            port_url, headers=self.admin, json={"proto": "TCP", "name": "collision"}
        )
        self.assertEqual(failed.status_code, 400)
        self.assertIn("already exists", failed.json["message"])
        with patch.object(Ports, "check_available"):
            self.assertEqual(
                self.client.put(
                    port_url, headers=self.admin, json={"proto": "TCP"}
                ).status_code,
                400,
            )
        self.assertEqual(
            self.client.get(port_url, headers=self.admin).json["result"]["name"], "web"
        )
        self.assertEqual(
            self.client.put(
                port_url, headers=self.admin, json={"name": "dns"}
            ).status_code,
            200,
        )
        g.pop("_login_user", None)
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.builder.sm.find_user(username="Admin").id)
            session["_fresh"] = True
        form = {"value": "80", "proto": str(self.tcp.id), "name": "GUI"}
        for url in ("/portsview/add", f"/portsview/edit/{udp}"):
            result = self.client.post(url, data=form)
            self.assertIn(b"Port TCP:80 already exists", result.data)
        self.assertEqual(
            self.client.post(f"/portsview/edit/{tcp}", data=form).status_code, 302
        )
        self.assertEqual(
            self.client.post(
                "/portsview/add", data={**form, "value": "81"}
            ).status_code,
            302,
        )
        self.assertEqual(self.create_port("TCP", 81).status_code, 400)
        picker = self.client.get(
            "/scanprofilesview/ports_remote", query_string={"q": "tcp:80"}
        )
        self.assertEqual(picker.json, [{"id": tcp, "text": "TCP:80"}])

    def test_profile_api_after_migration(self):
        """Detail returns the surviving IDs, and a stale ID is rejected on update."""
        kept = self.create_port("TCP", 80).json["result"]["id"]
        udp = self.create_port("UDP", 80).json["result"]["id"]
        created = self.client.post(
            self.url,
            headers=self.admin,
            json={"name": "legacy", "apply_to_all": True, "port_ids": [kept, udp]},
        )
        self.assertEqual(created.status_code, 201, created.json)
        profile_id = created.json["result"]["id"]
        profile = self.url + str(profile_id)
        # Reproduce a profile linked by the old GUI before the schema upgrade.
        self.db.session.execute("DROP INDEX uq_ports_proto_value")
        removed = self.db.session.execute(
            "INSERT INTO ports(value,name,proto_id,proto_to_port) VALUES(80,'legacy',:proto,'TCP:80')",
            {"proto": self.tcp.id},
        ).lastrowid
        self.db.session.execute(
            "UPDATE scanprofiles_ports_assoc SET port_id=:removed WHERE port_id=:kept AND scanprofile_id=:profile",
            {"removed": removed, "kept": kept, "profile": profile_id},
        )
        self.db.session.commit()
        self.db.session.remove()
        conn = self.db.engine.raw_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            MIGRATE(conn)
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(
            self.client.get(profile, headers=self.admin).json["result"]["port_ids"],
            sorted([kept, udp]),
        )
        self.assertEqual(
            self.client.get(
                self.ports_url + str(removed), headers=self.admin
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                profile, headers=self.admin, json={"port_ids": [removed]}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.put(
                profile, headers=self.admin, json={"port_ids": [kept]}
            ).status_code,
            200,
        )

    def test_fresh_schema_and_pair_change(self):
        """Direct inserts obey the composite index even with a different legacy key."""
        port = self.create_port("TCP", 80).json["result"]["id"]
        with self.assertRaises(IntegrityError):
            self.db.session.execute(
                Ports.__table__.insert().values(
                    value=80,
                    proto_id=self.tcp.id,
                    name="duplicate",
                    proto_to_port="TCP:80",
                )
            )
        self.db.session.rollback()
        response = self.client.put(
            self.ports_url + str(port),
            headers=self.admin,
            json={"proto": "UDP", "value": 53},
        )
        self.assertEqual(response.status_code, 200, response.json)
        item = self.db.session.query(Ports).filter_by(id=port).one()
        self.assertEqual(item.proto_to_port, f"53:{item.proto.id}")
        self.assertEqual(self.create_port("TCP", 80).status_code, 201)

    def test_concurrent_create(self):
        """Let both HTTP requests pass validation before either commits."""
        check = Ports.check_available
        ready = Barrier(2)

        def concurrent_check(*args):
            check(*args)
            ready.wait(timeout=10)

        def post():
            with self.app.test_client() as client:
                response = client.post(
                    self.ports_url,
                    headers=self.admin,
                    json={"proto": "TCP", "value": 80, "name": "web"},
                )
                return response.status_code

        with patch.object(
            Ports, "check_available", side_effect=concurrent_check
        ), ThreadPoolExecutor(max_workers=2) as pool:
            requests = [pool.submit(post) for _ in range(2)]
            self.assertEqual(sorted(result.result() for result in requests), [201, 400])
        self.assertEqual(self.db.session.query(Ports).count(), 1)

    def test_seed_twice(self):
        """Bulk setup preserves an existing service description and its ID."""
        saved = self.create_port("TCP", 80).json["result"]
        with patch("app.app", self.app), patch("app.db", self.db), patch.object(
            initial_setup, "TCP_PORT_MIN", 79
        ), patch.object(initial_setup, "TCP_PORT_MAX", 81):
            initial_setup.seed_tcp_ports()
            initial_setup.seed_tcp_ports()
        self.assertEqual(self.db.session.query(Ports).count(), 3)
        self.assertEqual(
            self.client.get(self.ports_url + str(saved["id"]), headers=self.admin).json[
                "result"
            ],
            saved,
        )
