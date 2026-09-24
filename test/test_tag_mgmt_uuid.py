"""Tests for UUID-based YAML selection in the tag management CLI."""

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase


TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS_DIR))
from tag_mgmt import get_yaml_files  # pylint: disable=wrong-import-position


class TagManagementUuidTests(TestCase):
    """Ensure rule filenames and display names cannot select the wrong rule."""

    def test_rule_id_import_locates_yaml_by_uuid(self):
        """Find the matching YAML despite an unrelated filename and duplicate name."""
        source_uuid = "9fc4762c-406d-4765-9c72-1353ae8579ae"
        with tempfile.TemporaryDirectory() as directory:
            tags_dir = Path(directory)
            source_path = tags_dir / "unrelated-filename.yaml"
            source_path.write_text(
                f"uuid: {source_uuid}\nname: Shared display name\n",
                encoding="utf-8",
            )
            args = SimpleNamespace(tags_file=None, tags_dir=str(tags_dir), all=False)
            self.assertEqual(get_yaml_files(args, rule_uuid=source_uuid), [source_path])
