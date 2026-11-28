"""Frozen parser revisions survive only an explicitly compatible storage fix."""

import unittest
from pathlib import Path
from unittest.mock import patch

from app.utils.index_revision_compat import compatible_code_revision
from app.utils.tag_reconciliation import code_revision

PRE_COPY_FIX_REVISION = (
    "0b328bca199730c3db289ebc6a7ea7ad835418f48b32102006d186c7622032f907"
    "2408cadd38b2be55a4e1b479bd0b9c6790d1a645f6beab70f4d0e996342509"
)
COPY_FIX_BUILD = (
    "a15d58e516d701c284361138b729c3d0f64f02437b8c1be5ed63b00452dbf9b923"
    "a98bcacb722f26fde4194277173ff1d6ccd195099ebcb467a0d20d1fdce31f"
)


class StorageRevisionTest(unittest.TestCase):
    """A storage fix must neither invalidate frozen inputs nor hide new code."""

    def test_reverse_read_adapter_keeps_pre_fix_frozen_revision(self):
        """The allowlist addition must not restart existing retagging work."""
        root = Path(__file__).resolve().parents[1] / "webapp" / "app" / "utils"
        original = Path.read_text
        current = code_revision()

        def before_fix(path, *args, **kwargs):
            content = original(path, *args, **kwargs)
            if path == root / "index_generations.py":
                content = content.replace('        "zrevrangebyscore",\n', '')
            return content

        with patch.object(Path, "read_text", before_fix):
            self.assertEqual(current, code_revision())

    def test_copy_fix_keeps_published_coverage_and_frozen_revision(self):
        """Existing jobs and document coverage use the pre-fix fingerprint."""
        self.assertEqual(
            compatible_code_revision(COPY_FIX_BUILD), PRE_COPY_FIX_REVISION
        )

    def test_service_extraction_requires_new_document_coverage(self):
        """Archived documents need reparsing to populate the observed service field."""
        self.assertNotEqual(code_revision(), PRE_COPY_FIX_REVISION)

    def test_other_code_changes_still_invalidate_the_revision(self):
        """Neither parser nor subsequent storage edits inherit this exception."""
        root = Path(__file__).resolve().parents[1] / "webapp" / "app" / "utils"
        original = {
            path: path.read_text(encoding="utf-8") for path in root.glob("*.py")
        }
        current_revision = code_revision()
        for changed in ("result_parser.py", "index_generations.py"):
            with self.subTest(changed=changed):

                def edited(path, changed_file=changed, **_kwargs):
                    """Provide the edited test fixture."""
                    content = original[path]
                    return (
                        content + "\n# changed\n"
                        if path.name == changed_file
                        else content
                    )

                with patch.object(Path, "read_text", edited):
                    self.assertNotEqual(code_revision(), current_revision)

    def test_unknown_builds_are_not_aliased(self):
        """Compatibility is exact, never a global parser-version bypass."""
        self.assertEqual(compatible_code_revision("another-build"), "another-build")
