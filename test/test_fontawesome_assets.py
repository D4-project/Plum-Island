"""Verify matched Font Awesome assets override FAB without changing its URLs."""

import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from urllib.parse import urljoin

from flask import Blueprint, Flask
from jinja2 import ChoiceLoader, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "webapp/app/static"
SPEC = importlib.util.spec_from_file_location(
    "icon_assets", ROOT / "webapp/app/ui_assets.py"
)
ASSETS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSETS)


class FontAwesomeAssetsTest(unittest.TestCase):
    """Exercise real Flask static resolution, CSS dependencies and cache checks."""

    def setUp(self):
        """Use FAB's actual blueprint alongside the application asset overrides."""
        framework = Path(importlib.util.find_spec("flask_appbuilder").origin).parent
        self.app = Flask(
            "icon-assets", static_folder=str(STATIC), static_url_path="/static"
        )
        ASSETS.configure_icon_assets(self.app)
        self.app.register_blueprint(
            Blueprint(
                "appbuilder",
                __name__,
                static_folder=str(framework / "static/appbuilder"),
                static_url_path="/static/appbuilder",
            )
        )
        self.app.jinja_loader = ChoiceLoader(
            [self.app.jinja_loader, FileSystemLoader(framework / "templates")]
        )
        self.client = self.app.test_client()

    def read(self, url):
        """Close each file response after reading its bytes."""
        with self.client.get(url) as response:
            self.assertEqual(response.status_code, 200, url)
            return response.data

    def test_all_themes_load_matched_local_css_and_font_dependencies(self):
        """Plum and original themes resolve FA 6.7.2 via unchanged FAB URLs."""
        for theme in ("plum.css", "readable.css", "flatly.css"):
            with self.subTest(theme=theme), self.app.test_request_context():
                rendered = self.app.jinja_env.get_template(
                    "appbuilder/init.html"
                ).render(
                    appbuilder=SimpleNamespace(app_name="Icon probe", app_theme=theme)
                )
                urls = re.findall(r'href="([^"]*/fontawesome/[^"]+)"', rendered)
                self.assertEqual(len(urls), 5)
                fonts = set()
                for url in urls:
                    css = self.read(url).decode()
                    self.assertIn("Font Awesome Free 6.7.2", css)
                    for reference in re.findall(r'url\(["\']?([^"\')]+)', css):
                        font_url = urljoin(url, reference)
                        self.assertTrue(
                            font_url.startswith("/static/appbuilder/css/webfonts/")
                        )
                        fonts.add(font_url)
                        data = self.read(font_url)
                        self.assertTrue(
                            data.startswith(
                                b"wOF2"
                                if font_url.endswith(".woff2")
                                else b"\x00\x01\x00\x00"
                            )
                        )
                self.assertEqual(len(fonts), 6)

    def test_served_fonts_match_vendored_files_instead_of_fab(self):
        """Serve the same bytes to old bookmarks, font CSS and direct requests."""
        for name in ASSETS.FONT_AWESOME_FONTS:
            self.assertEqual(
                self.read("/static/appbuilder/css/webfonts/" + name),
                (STATIC / "vendor/fontawesome/webfonts" / name).read_bytes(),
            )
        self.assertTrue((STATIC / "vendor/fontawesome/LICENSE.txt").is_file())

    def test_revalidation_and_unrelated_static_files_are_preserved(self):
        """ETags work; non-icon static requests still use FAB's blueprint."""
        url = "/static/appbuilder/css/webfonts/fa-solid-900.woff2"
        with self.client.get(url) as response:
            etag = response.headers["ETag"]
        with self.client.get(url, headers={"If-None-Match": etag}) as response:
            self.assertEqual(response.status_code, 304)
        with self.client.get(
            url, headers={"If-None-Match": '"stale-fab-font"'}
        ) as response:
            self.assertEqual(response.status_code, 200)
        self.assertTrue(self.read("/static/appbuilder/css/ab.css"))
        with self.client.get(
            "/static/appbuilder/css/fontawesome/not-an-asset.css"
        ) as response:
            self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
