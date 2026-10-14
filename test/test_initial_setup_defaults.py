"""Installer default names and script sources, without application startup."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools import initial_setup


class InitialSetupDefaultsTest(unittest.TestCase):
    """Keep default labels descriptive and NSE selection explicit."""

    def test_tcp_service_catalogue(self):
        """Only valid TCP entries count; the first canonical name wins."""
        source = Mock()
        source.read_text.return_value = (
            "# services\nhttps 443/tcp alias # TLS\n"
            "tinc 655/tcp\nother 655/tcp\ndns 53/udp\n"
            "bad nope/tcp\nbad -1/tcp\nbad 65536/tcp\ninvalid\n"
        )
        names = initial_setup.load_tcp_service_names(source)
        self.assertEqual(names, {443: "https", 655: "tinc"})
        self.assertEqual(
            initial_setup.default_tcp_port_name(655, names), "TCP/655 (tinc)"
        )
        self.assertEqual(initial_setup.default_tcp_port_name(60000, names), "TCP/60000")
        source.read_text.side_effect = FileNotFoundError
        self.assertEqual(initial_setup.load_tcp_service_names(source), {})

    def test_default_scripts_and_bundled_fallback(self):
        """Prefer repository scripts; fill missing defaults from bundled files."""
        self.assertEqual(
            set(initial_setup.DEFAULT_SCAN_PROFILE_NSES),
            {
                "http-headers.nse",
                "http-title.nse",
                "ssl-cert.nse",
                "ssh-hostkey.nse",
                "tls-alpn.nse",
                "banner.nse",
                "modbus.nse",
                "http-mm-sha-favicon.nse",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repository"
            repo.mkdir()
            bundled = root / "nse"
            bundled.mkdir()
            (repo / "banner.nse").touch()
            (repo / "modbus.nse").touch()
            (bundled / "banner.nse").touch()
            (bundled / "http-headers.nse").touch()
            (bundled / "http-favicon.nse").touch()
            with patch.object(initial_setup, "BASE_DIR", root):
                files = list(initial_setup.iter_nse_files(repo))
            self.assertEqual(
                files,
                [
                    repo / "banner.nse",
                    repo / "modbus.nse",
                    bundled / "http-headers.nse",
                ],
            )


if __name__ == "__main__":
    unittest.main()
