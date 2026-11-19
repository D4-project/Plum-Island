"""Enforce the repository's SQL migration filename convention."""

from pathlib import Path
from unittest import TestCase, main


class SqlMigrationNamesTest(TestCase):
    """Migration filenames use a sequence number and full source commit SHA."""

    def test_names_and_sequence_numbers(self):
        """Reject short hashes, descriptive suffixes and duplicate numbers."""
        directory = Path(__file__).resolve().parents[1] / "webapp/sql_upd"
        scripts = sorted(directory.glob("*.py"))
        self.assertTrue(scripts)
        numbers = set()
        for script in scripts:
            with self.subTest(script=script.name):
                self.assertRegex(
                    script.name, r"^[0-9]{2,}_migrate_from_[0-9a-f]{40}\.py$"
                )
                number = int(script.name.split("_", 1)[0])
                self.assertNotIn(number, numbers)
                numbers.add(number)


if __name__ == "__main__":
    main()
