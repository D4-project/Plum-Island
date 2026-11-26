"""Isolated Docker bootstrap checks; no Docker daemon or application startup."""

from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


class DockerBootstrapTest(unittest.TestCase):
    """Check local dependency ordering and persistent configuration behavior."""

    def test_launcher_listens_on_compose_port(self):
        """The container launcher must listen on a port published by Compose."""
        services = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
        ports = services["plum-webapp"]["ports"]
        flask_module = ModuleType("app")
        flask_module.app = Mock()
        with patch.dict(sys.modules, {"app": flask_module}):
            runpy.run_path(str(ROOT / "webapp/run.py"))
        flask_module.app.run.assert_called_once()
        port = str(flask_module.app.run.call_args.kwargs["port"])
        self.assertIn(port, [binding.rsplit(":", 1)[-1] for binding in ports])

    def test_editable_dependency_available_before_install(self):
        """A clean build must copy the editable package before invoking pip."""
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("-e ./webapp/tags", (ROOT / "requirements.txt").read_text())
        self.assertLess(
            dockerfile.index("COPY webapp/tags/ ./webapp/tags/"),
            dockerfile.index("RUN pip install --no-cache-dir -r requirements.txt"),
        )
        self.assertTrue((ROOT / "webapp/tags/pyproject.toml").is_file())

    def test_config_generation_and_existing_config_preservation(self):
        """Bootstrap enables PDNS with credentials and preserves existing config."""
        with tempfile.TemporaryDirectory(prefix="plum-entrypoint-test-") as folder:
            workdir = Path(folder)
            database = workdir / "app.db"
            database.touch()
            script = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
            script = script.replace(
                'DB_PATH="/plum/data/app.db"', f'DB_PATH="{database}"'
            )
            entrypoint = workdir / "entrypoint.sh"
            entrypoint.write_text(script, encoding="utf-8")
            (workdir / "config.py.template").write_text(
                (ROOT / "webapp/config.py.template").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            # Intercept every Python/Flask invocation; never start the app or SQL.
            for executable in ("python", "flask"):
                stub = workdir / executable
                stub.write_text(
                    '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALL_LOG"\n',
                    encoding="utf-8",
                )
                stub.chmod(0o700)
            log = workdir / "calls.log"
            env = {
                "PATH": f"{workdir}:/usr/bin:/bin",
                "CALL_LOG": str(log),
                "MEILI_KEY": "synthetic-test-key",
                "SECRET_KEY": "synthetic-test-secret",
                "MEILI_DATABASE_URI": "http://plum-meilisearch:7700",
                "KVROCKS_HOST": "plum-kvrocks",
            }
            subprocess.run(
                ["bash", str(entrypoint)],
                cwd=workdir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            config_path = workdir / "config.py"
            generated = config_path.read_text(encoding="utf-8")
            self.assertIn('SECRET_KEY = "synthetic-test-secret"', generated)
            self.assertIn('KVROCKS_HOST = "plum-kvrocks"', generated)
            self.assertIn(f"sqlite:///{database}", generated)
            self.assertIn("PDNS_ENABLED = False", generated)
            config_path.unlink()
            env.update(PASSIVE_USER="test@example.org", PASSIVE_PWD="test-pdns-key")
            subprocess.run(
                ["bash", str(entrypoint)],
                cwd=workdir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            generated = config_path.read_text(encoding="utf-8")
            self.assertIn("PDNS_ENABLED = True", generated)
            custom = generated.replace("PDNS_ENABLED = True", "PDNS_ENABLED = False")
            custom += '\nREPORT_SMTP_FROM = "reports@example.org"\n'
            config_path.write_text(custom, encoding="utf-8")
            config_path.chmod(0o400)
            env.pop("MEILI_KEY")
            env["SECRET_KEY"] = "must-not-replace-saved-config"
            subprocess.run(
                ["bash", str(entrypoint)],
                cwd=workdir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(config_path.read_text(encoding="utf-8"), custom)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["../tools/initial_setup.py --roles-only", "run.py"] * 3,
            )
            self.assertEqual(database.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
