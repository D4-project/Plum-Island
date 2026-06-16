"""
Regression tests for target CIDR coverage checks.
"""

import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app import app, db  # pylint: disable=wrong-import-position
from app.models import Targets  # pylint: disable=wrong-import-position
from app.views import TargetsView  # pylint: disable=wrong-import-position


class TargetCoverageTest(unittest.TestCase):
    """
    Validate CIDR containment lookup before target insert.
    """

    VALUES = (
        "99.254.0.0/16",
        "99.254.10.0/24",
        "99.255.10.0/24",
        "99.254.20.0/24",
    )

    def setUp(self):
        self.context = app.app_context()
        self.context.push()
        self._delete_values()
        db.session.add(Targets(value=self.VALUES[0], description="coverage test"))
        db.session.commit()

    def tearDown(self):
        self._delete_values()
        self.context.pop()

    def _delete_values(self):
        db.session.query(Targets).filter(Targets.value.in_(self.VALUES)).delete(
            synchronize_session=False
        )
        db.session.commit()

    def test_subnet_is_covered_by_existing_larger_cidr(self):
        target = TargetsView.find_covering_target(self.VALUES[1])

        self.assertIsNotNone(target)
        self.assertEqual(target.value, self.VALUES[0])

    def test_exact_existing_cidr_is_covered(self):
        target = TargetsView.find_covering_target(self.VALUES[0])

        self.assertIsNotNone(target)
        self.assertEqual(target.value, self.VALUES[0])

    def test_exact_existing_cidr_excludes_self_on_update(self):
        existing = db.session.query(Targets).filter_by(value=self.VALUES[0]).one()

        self.assertIsNone(
            TargetsView.find_covering_target(self.VALUES[0], exclude_id=existing.id)
        )

    def test_unrelated_cidr_is_not_covered(self):
        self.assertIsNone(TargetsView.find_covering_target(self.VALUES[2]))

    def test_gui_pre_add_rejects_covered_cidr(self):
        view = TargetsView()
        item = Targets(value=self.VALUES[1], description="covered")

        with self.assertRaisesRegex(Exception, "already covered"):
            view.pre_add(item)

    def test_gui_pre_update_rejects_covered_cidr(self):
        item = Targets(value=self.VALUES[3], description="covered")
        db.session.add(item)
        db.session.commit()

        item.value = self.VALUES[1]
        with self.assertRaisesRegex(Exception, "already covered"):
            TargetsView().pre_update(item)


if __name__ == "__main__":
    unittest.main()
