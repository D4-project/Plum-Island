"""Exercise the profile REST contract in a private Flask app with no scheduler."""

import importlib.util
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from flask import Flask
from flask_appbuilder import AppBuilder, SQLA
from sqlalchemy.exc import IntegrityError
from app import apis
from app.models import Ports, Protos, ScanProfiles


class ProfileApiFixture(unittest.TestCase):
    """Run real JWT and database checks against a disposable SQLite database."""

    def configure_catalogue(self):
        """Register routes before the first request reaches the fixture app."""
        self.builder.add_api(apis.ScanProfilesApi)

    def database_uri(self):
        """Use an isolated in-memory database for sequential requests."""
        return "sqlite://"

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SECRET_KEY="isolated-test-key-for-jwt-0123456789",
            SQLALCHEMY_DATABASE_URI=self.database_uri(),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            WTF_CSRF_ENABLED=False,
        )
        self.enterContext(self.app.app_context())
        self.db = SQLA(self.app)
        self.addCleanup(self.db.engine.dispose)
        self.addCleanup(self.db.session.remove)
        self.builder = AppBuilder(self.app, self.db.session)
        self.configure_catalogue()
        self.enterContext(patch.object(apis, "db", self.db))
        self.client = self.app.test_client()
        self.url = "/api/v1/scanprofiles/"
        self.admin = self.login("Admin")
        self.db.session.add(Protos(id=1, value="fixture", name="fixture"))
        self.db.session.commit()

    def login(self, role_name):
        """Create a local user and obtain a token through the actual login route."""
        sm = self.builder.sm
        role = sm.find_role(role_name) or sm.add_role(role_name)
        user = sm.add_user(
            role_name,
            "Local",
            "Test",
            role_name + "@example.invalid",
            role,
            password="local-fixture",
        )
        self.assertIsNotNone(user)
        response = self.client.post(
            "/api/v1/security/login",
            json={
                "username": role_name,
                "password": "local-fixture",
                "provider": "db",
            },
        )
        self.assertEqual(response.status_code, 200, response.json)
        return {"Authorization": "Bearer " + response.json["access_token"]}


class ProfileRestTest(ProfileApiFixture):
    """Exercise profile reads and writes through real HTTP requests."""

    def ports(self, count):
        """Seed inert catalogue records. No targets or agents exist in this app."""
        self.db.session.execute(
            Ports.__table__.insert(),
            [
                {
                    "id": i,
                    "value": i,
                    "name": "fixture",
                    "proto_id": 1,
                    "proto_to_port": str(i),
                }
                for i in range(1, count + 1)
            ],
        )
        self.db.session.commit()

    def test_crud_and_rollback(self):
        """A rejected partial update preserves the entire record."""
        self.ports(2)

        def create(name):
            response = self.client.post(
                self.url, headers=self.admin, json={"name": name, "port_ids": [1]}
            )
            self.assertEqual(response.status_code, 201, response.json)
            return self.url + str(response.json["result"]["id"])

        path = create("B")
        create("A")

        def update(**fields):
            return self.client.put(path, headers=self.admin, json=fields)

        self.assertEqual(update(name="B2", port_ids=[2]).status_code, 200)
        before = self.client.get(path, headers=self.admin).json["result"]
        self.assertEqual(before["port_ids"], [2])
        self.assertEqual(update(name="A").status_code, 400)
        self.assertEqual(update(name="B3", port_ids=[100]).status_code, 400)
        self.assertEqual(
            self.client.get(path, headers=self.admin).json["result"], before
        )
        for page, name in [(1, "A"), (2, "B2")]:
            response = self.client.get(
                self.url,
                headers=self.admin,
                query_string={"page": page, "page_size": 1},
            )
            self.assertEqual(response.json["total"], 2)
            self.assertEqual([p["name"] for p in response.json["result"]], [name])
            self.assertNotIn("port_ids", response.json["result"][0])
            self.assertNotIn("nse_ids", response.json["result"][0])
        self.assertEqual(
            self.client.get(
                self.url + "?page_size=101", headers=self.admin
            ).status_code,
            400,
        )
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 404)
        self.db.session.add(ScanProfiles(name="A"))
        with self.assertRaises(IntegrityError):
            self.db.session.commit()
        self.db.session.rollback()

    def test_permissions(self):
        """List-only credentials grant exactly one of the five methods."""
        role = self.builder.sm.add_role("ProfileLister")
        role.permissions = [
            self.builder.sm.find_permission_view_menu("can_list", "ScanProfilesApi")
        ]
        self.db.session.commit()
        headers = self.login("ProfileLister")
        for method, suffix in (
            ("GET", ""),
            ("POST", ""),
            ("GET", "1"),
            ("PUT", "1"),
            ("DELETE", "1"),
        ):
            self.assertIn(
                self.client.open(self.url + suffix, method=method).status_code,
                (401, 403),
            )
            response = self.client.open(
                self.url + suffix, method=method, headers=headers
            )
            self.assertEqual(
                response.status_code, 200 if (method, suffix) == ("GET", "") else 403
            )

    def test_large_json_round_trip_and_request_limit(self):
        """A large inactive catalogue association round-trips within the byte limit."""
        count = 65535
        self.ports(count)
        ids = list(range(1, count + 1))
        body = json.dumps({"name": "Fixture", "port_ids": ids}, separators=(",", ":"))

        def post():
            return self.client.post(
                self.url, headers=self.admin, data=body, content_type="application/json"
            )

        with patch.dict(self.app.config, MAX_CONTENT_LENGTH=len(body) - 1):
            self.assertEqual(post().status_code, 413)
        with patch.dict(self.app.config, MAX_CONTENT_LENGTH=len(body)):
            response = post()
        self.assertEqual(response.status_code, 201, response.json.get("message"))
        url = self.url + str(response.json["result"]["id"])
        result = self.client.get(url, headers=self.admin).json["result"]
        self.assertFalse(result["apply_to_all"])
        self.assertEqual(result["port_ids"], ids)


class ProfileNameMigrationTest(unittest.TestCase):
    """Migration 25 protects IDs and associations when resolving old duplicates."""

    def test_duplicate_diagnostics_and_rerun(self):
        """Report conflicting IDs and allow a safe retry after resolving them."""
        path = next(
            (Path(__file__).resolve().parents[1] / "webapp/sql_upd").glob("25_*.py")
        )
        spec = importlib.util.spec_from_file_location("migration25", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE scanprofiles(id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        db.executemany(
            "INSERT INTO scanprofiles VALUES(?,?)", [(1, "Profile"), (2, "Profile")]
        )
        with self.assertRaisesRegex(ValueError, "1,2"):
            module.migrate(db)
        self.assertEqual(
            db.execute("SELECT count(*) FROM scanprofiles").fetchone()[0], 2
        )
        db.execute("UPDATE scanprofiles SET name='Other' WHERE id=2")
        module.migrate(db)
        module.migrate(db)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT INTO scanprofiles VALUES(3,'Other')")
