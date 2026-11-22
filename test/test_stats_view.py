"""Regression checks for the operational Stats view."""

import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


class StatsViewTest(unittest.TestCase):
    """Stats must count each port configured by a scan profile only once."""

    def test_unique_scan_profile_ports_are_exposed_to_template(self):
        """The Stats view queries distinct profile-associated port records."""
        tree = ast.parse((ROOT / "webapp/app/views.py").read_text())
        view = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "StatsView"
        )
        view.bases = []
        view.body = [
            node
            for node in view.body
            if isinstance(node, ast.FunctionDef) and node.name == "index"
        ]
        view.body[0].decorator_list = []

        class TargetValue:
            """Regression checks for target value."""

            value = "value"

        class PortId:
            """Regression checks for port id."""

            id = "id"
            scanprofiles = "scanprofiles"

        class Query:
            """Regression checks for query."""

            def __init__(self, rows=None):
                """Provide the init test fixture."""
                self.rows = rows or []

            def all(self):
                """Provide the all test fixture."""
                return self.rows

            def join(self, _relationship):
                """Provide the join test fixture."""
                return self

            def distinct(self):
                """Provide the distinct test fixture."""
                return self

            def count(self):
                """Provide the count test fixture."""
                return 7

        class Session:
            """Regression checks for session."""

            def query(self, field):
                """Provide the query test fixture."""
                return Query([] if field == TargetValue.value else None)

        indexer = SimpleNamespace(
            objects_count=lambda: {"ip_count": 11, "uid_count": 19}
        )
        namespace = {
            "Targets": TargetValue,
            "Ports": PortId,
            "db": SimpleNamespace(
                session=Session(),
                app=SimpleNamespace(config={"KVROCKS_IDX": indexer}),
            ),
            "is_valid_fqdn": lambda _value: False,
            "is_valid_ip": lambda _value: False,
            "is_valid_cidr": lambda _value: False,
            "IPNetwork": None,
            "KVrocksIndexer": None,
            "utcnow_naive": lambda: None,
            "request": SimpleNamespace(args={"tab": "overview"}),
            "activity_series": Mock(return_value={}),
        }
        module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
        exec(compile(module, "<isolated StatsView>", "exec"), namespace)
        instance = namespace["StatsView"]()
        instance.render_template = lambda _name, **context: context

        context = instance.index()
        self.assertEqual(context["stats"]["scanned_port_count"], 7)
        self.assertEqual(context["stats"]["kv_scanned_host_count"], 11)
        self.assertEqual(context["stats"]["kv_scan_result_count"], 19)
        self.assertEqual(context["stats_tab"], "overview")
        namespace["activity_series"].assert_not_called()

        # Graphs read only the activity buckets, never the old inventory totals.
        namespace["request"].args = {"period": "bad", "tool": "bad"}
        namespace["db"].session.query = Mock(
            side_effect=AssertionError("inventory query")
        )
        graphs = instance.index()
        self.assertEqual(graphs["stats_tab"], "graphs")
        self.assertNotIn("stats", graphs)
        namespace["activity_series"].assert_called_once_with(
            namespace["db"].session, None, "hour", "all"
        )


if __name__ == "__main__":
    unittest.main()
