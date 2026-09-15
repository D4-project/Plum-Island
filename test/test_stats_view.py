"""Regression checks for the operational Stats view."""

import ast
import unittest
from pathlib import Path
from types import SimpleNamespace


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
            node for node in view.body if isinstance(node, ast.FunctionDef) and node.name == "index"
        ]
        view.body[0].decorator_list = []

        class TargetValue:
            value = "value"

        class PortId:
            id = "id"
            scanprofiles = "scanprofiles"

        class Query:
            def __init__(self, rows=None):
                self.rows = rows or []

            def all(self):
                return self.rows

            def join(self, _relationship):
                return self

            def distinct(self):
                return self

            def count(self):
                return 7

        class Session:
            def query(self, field):
                return Query([] if field == TargetValue.value else None)

        indexer = SimpleNamespace(objects_count=lambda: {"ip_count": 11, "uid_count": 19})
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
        }
        module = ast.fix_missing_locations(ast.Module(body=[view], type_ignores=[]))
        exec(compile(module, "<isolated StatsView>", "exec"), namespace)
        instance = namespace["StatsView"]()
        instance.render_template = lambda _name, **context: context

        context = instance.index()
        self.assertEqual(context["stats"]["scanned_port_count"], 7)
        self.assertEqual(context["stats"]["kv_scanned_host_count"], 11)
        self.assertEqual(context["stats"]["kv_scan_result_count"], 19)


if __name__ == "__main__":
    unittest.main()
