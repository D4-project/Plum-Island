"""Regression tests for shared Plum-Antibodies tag syntax validation."""

import unittest

from app.utils.tagrules import normalize_tags, parse_tags_text
from plum_antibodies import TagValidationError, validate_tag


class TagSyntaxTests(unittest.TestCase):
    """Ensure UI/import code delegates tag syntax to Plum-Antibodies."""

    def test_normalization_uses_the_shared_library(self):
        """Normalize valid and legacy tag values through the shared API."""
        self.assertEqual(
            normalize_tags(["TAG:Vendor:Cisco", "cpe:cisco:ios"]),
            ["vendor:cisco", "cpe:cisco:ios"],
        )

    def test_invalid_tag_cannot_be_prepared_for_insertion(self):
        """Reject malformed UI/import tag values before persistence."""
        with self.assertRaises(TagValidationError):
            parse_tags_text("product:bad tag")

    def test_empty_document_tag_sets_remain_valid(self):
        """Allow scan documents to have no computed tags."""
        self.assertEqual(normalize_tags([]), [])

    def test_library_reports_the_same_invalid_syntax(self):
        """Expose the canonical validation behavior to consumers."""
        with self.assertRaises(TagValidationError):
            validate_tag("product")
