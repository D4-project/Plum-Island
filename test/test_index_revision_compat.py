"""Frozen parser revisions survive only an explicitly compatible storage fix."""

from pathlib import Path
import unittest
from unittest.mock import patch

from app.utils.index_revision_compat import compatible_code_revision
from app.utils.tag_reconciliation import code_revision

PRE_COPY_FIX_REVISION = (
    "0b328bca199730c3db289ebc6a7ea7ad835418f48b32102006d186c7622032f907"
    "2408cadd38b2be55a4e1b479bd0b9c6790d1a645f6beab70f4d0e996342509"
)


class StorageRevisionTest(unittest.TestCase):
    """A storage fix must neither invalidate frozen inputs nor hide new code."""

    def test_copy_fix_keeps_published_coverage_and_frozen_revision(self):
        """Existing jobs and document coverage use the pre-fix fingerprint."""
        self.assertEqual(code_revision(), PRE_COPY_FIX_REVISION)

    def test_other_code_changes_still_invalidate_the_revision(self):
        """Neither parser nor subsequent storage edits inherit this exception."""
        root = Path(__file__).resolve().parents[1] / "webapp" / "app" / "utils"
        original = {
            path: path.read_text(encoding="utf-8") for path in root.glob("*.py")
        }
        for changed in ("result_parser.py", "index_generations.py"):
            with self.subTest(changed=changed):

                def edited(path, changed_file=changed, **_kwargs):
                    content = original[path]
                    return (
                        content + "\n# changed\n" if path.name == changed_file else content
                    )

                with patch.object(Path, "read_text", edited):
                    self.assertNotEqual(code_revision(), PRE_COPY_FIX_REVISION)

    def test_unknown_builds_are_not_aliased(self):
        """Compatibility is exact, never a global parser-version bypass."""
        self.assertEqual(compatible_code_revision("another-build"), "another-build")
