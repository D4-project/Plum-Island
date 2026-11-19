"""Check that Plum's stylesheet, fonts and JSON modules resolve locally."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
from unittest import TestCase, skipUnless
from urllib.parse import urljoin, urlsplit

from flask import Blueprint, Flask

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "webapp/app/static"
ORIGIN = "http://plum.test"


class PlumOfflineAssetsTest(TestCase):
    """Traverse real asset dependencies without application or database startup."""

    def setUp(self):
        """Use the same static URL layout as Flask and Flask-AppBuilder."""
        framework = Path(importlib.util.find_spec("flask_appbuilder").origin).parent
        app = Flask(
            "offline-assets", static_folder=str(STATIC), static_url_path="/static"
        )
        app.register_blueprint(
            Blueprint(
                "appbuilder",
                __name__,
                static_folder=str(framework / "static/appbuilder"),
                static_url_path="/static/appbuilder",
            )
        )
        for name in ("plum.css", "plum-components.css"):
            app.add_url_rule(
                f"/static/appbuilder/css/themes/{name}",
                endpoint=name,
                view_func=app.send_static_file,
                defaults={"filename": f"appbuilder/css/themes/{name}"},
            )
        self.client = app.test_client()

    def local_url(self, parent, reference):
        """Reject remote dependencies and resolve relative paths as browsers do."""
        target = urlsplit(urljoin(parent, reference))
        self.assertEqual(target.scheme, "http", reference)
        self.assertEqual(target.netloc, "plum.test", reference)
        return ORIGIN + target.path

    def read_asset(self, url):
        """Fetch an actual static response and close its file-backed stream."""
        with self.client.get(urlsplit(url).path) as response:
            self.assertEqual(response.status_code, 200, url)
            return response.data

    def test_plum_stylesheets_and_all_referenced_fonts_are_local_and_available(self):
        """Detect external imports even when they are several CSS imports deep."""
        pending = [ORIGIN + "/static/appbuilder/css/themes/plum.css"]
        visited = set()
        while pending:
            url = pending.pop()
            if url in visited:
                continue
            visited.add(url)
            content = self.read_asset(url)
            if url.endswith(".woff2"):
                self.assertTrue(content.startswith(b"wOF2"), url)
            if not url.endswith(".css"):
                continue
            source = re.sub(r"/\*.*?\*/", "", content.decode(), flags=re.S)
            references = re.findall(r"url\(\s*['\"]?([^)'\"\s]+)", source)
            references += re.findall(r"@import\s+['\"]([^'\"]+)", source)
            for reference in references:
                if reference.startswith(("data:", "#")):
                    continue
                pending.append(self.local_url(url, reference))
        self.assertTrue(any("vendor/raleway/" in url for url in visited))
        self.assertTrue(any("glyphicons-halflings" in url for url in visited))

    def test_raleway_preserves_both_weights_and_all_unicode_subsets(self):
        """Retain accented/non-Latin coverage as well as regular and bold text."""
        source = (STATIC / "vendor/raleway/raleway.css").read_text()
        faces = re.findall(r"@font-face\s*\{([^}]+)\}", source)
        for weight in (400, 700):
            matching = [face for face in faces if f"font-weight: {weight};" in face]
            self.assertEqual(len(matching), 5)
            self.assertTrue(all("unicode-range:" in face for face in matching))
        self.assertTrue((STATIC / "vendor/raleway/OFL.txt").is_file())

    @skipUnless(shutil.which("node"), "Node.js required for parsing ES module imports")
    def test_vitrine_module_imports_are_local_and_available(self):
        """The locally bundled JSON viewer must not import modules from a CDN."""
        pending = [ORIGIN + "/static/vendor/vitrine/esm/vt-json.js"]
        visited = set()
        while pending:
            url = pending.pop()
            if url in visited:
                continue
            visited.add(url)
            source = self.read_asset(url).decode()
            parsed = subprocess.run(
                [
                    shutil.which("node"),
                    "--experimental-vm-modules",
                    "-e",
                    "const vm = require('node:vm'); let source = '';"
                    "process.stdin.on('data', chunk => source += chunk);"
                    "process.stdin.on('end', () => process.stdout.write(JSON.stringify("
                    "new vm.SourceTextModule(source).dependencySpecifiers)));",
                ],
                input=source,
                text=True,
                capture_output=True,
                check=True,
                timeout=20,
            )
            for reference in json.loads(parsed.stdout):
                pending.append(self.local_url(url, reference))
        self.assertGreater(len(visited), 1)
