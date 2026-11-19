"""Regression checks for Target Show structured-search behavior."""

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TargetShowResultsTest(unittest.TestCase):
    """Keep Target Show wired to the shared tags and navigation contracts."""

    def test_target_template_uses_exact_range_and_shared_tag_enricher(self):
        """Target results load tags after rendering and retain the target time scope."""
        template = (ROOT / "webapp/app/templates/show_targetsview.html").read_text()
        views = (ROOT / "webapp/app/views.py").read_text()
        self.assertIn("js/ip_tag_enrichment.js", template)
        self.assertIn("targetTagEnricher.queue(results, targetSearchTimeRange)", template)
        self.assertIn("ipLink.href = `/ip/${encodeURIComponent(ip)}`", template)
        self.assertIn("detailLink.setAttribute('data-toggle', 'collapse')", template)
        self.assertIn("from_date = min(timestamps)", views)
        self.assertNotIn("from_date = min(timestamps) - timedelta(days=1)", views)

    @unittest.skipUnless(shutil.which("node"), "Node.js required for browser checks")
    def test_shared_tag_enricher(self):
        """Exercise its batching, range forwarding, normalization and deduplication."""
        subprocess.run(
            [shutil.which("node"), str(Path(__file__).with_name("target_show_results_ui.js"))],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
