"""Check diagnostics against real redis-py dispatch without external services."""

import sys
import shutil
import subprocess
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp/app/utils"))
from search_debug import SearchDiagnostics  # pylint: disable=wrong-import-position


class SearchDebugClientTest(unittest.TestCase):
    """Preserve lazy SCAN and pipeline execution/reset semantics."""

    @unittest.skipUnless(
        shutil.which("node"), "Node.js required for template-script checks"
    )
    def test_browser_report(self):
        """Exercise the actual JavaScript report, including stale-response guards."""
        subprocess.run(
            [shutil.which("node"), str(Path(__file__).with_name("search_debug_ui.js"))],
            check=True,
            timeout=20,
            capture_output=True,
            text=True,
        )

    def test_scan_counts_actual_iterations_without_extra_commands(self):
        """SCAN timing excludes Python work between generator yields."""
        client = redis.Redis()
        execute = Mock(side_effect=[(7, ["key1", "key2"]), (0, ["key3"])])
        with patch.object(client, "execute_command", execute):
            with ExitStack() as cleanup:
                diagnostics = SearchDiagnostics(cleanup)
                diagnostics.instrument(client)
                iterator = client.scan_iter(match="http_server:*", count=1000)
                self.assertEqual(execute.call_count, 0)
                self.assertEqual(next(iterator), "key1")
                self.assertEqual(execute.call_count, 1)
                self.assertEqual(list(iterator), ["key2", "key3"])
                stats = diagnostics.report()["kvrocks"]["commands"]["SCAN"]
                self.assertEqual(stats["direct_calls"], 2)
                self.assertEqual(stats["reply_items"], 3)
                self.assertEqual(stats["max_reply_items"], 2)
            self.assertIs(client.execute_command, execute)
        self.assertNotIn("execute_command", vars(client))

    def test_real_pipelines_keep_transaction_mode_and_count_executed_commands(self):
        """Use real command queues and execute/reset, mocking only server I/O."""
        client = redis.Redis()
        connection = Mock()
        connection.retry.call_with_retry.side_effect = (
            lambda operation, *_args, **_kwargs: operation()
        )
        with patch.object(
            client.connection_pool, "get_connection", return_value=connection
        ):
            with patch.object(client.connection_pool, "release"):
                with ExitStack() as cleanup:
                    diagnostics = SearchDiagnostics(cleanup)
                    diagnostics.instrument(client)
                    for transaction in (True, False):
                        with client.pipeline(transaction=transaction) as pipe:
                            self.assertEqual(pipe.transaction, transaction)
                            pipe.get("uid:secret").hgetall("doc:secret")
                            self.assertEqual(
                                diagnostics.kvrocks["pipeline_executions"],
                                2 * int(not transaction),
                            )
                            method = (
                                "_execute_transaction"
                                if transaction
                                else "_execute_pipeline"
                            )
                            with patch.object(
                                pipe,
                                method,
                                return_value=["private-ip", {"ip": "private-ip"}],
                            ):
                                self.assertEqual(
                                    pipe.execute(), ["private-ip", {"ip": "private-ip"}]
                                )
                            self.assertEqual(pipe.command_stack, [])
                            # Reuse an empty pipeline: no phantom command counts.
                            self.assertEqual(pipe.execute(), [])
                    stats = diagnostics.report()["kvrocks"]
                    self.assertEqual(stats["pipeline_executions"], 4)
                    self.assertEqual(stats["max_pipeline_commands"], 2)
                    self.assertEqual(stats["commands"]["GET"]["pipeline_calls"], 2)
                    self.assertEqual(stats["commands"]["HGETALL"]["reply_items"], 2)
                    self.assertNotIn("private", str(stats))
        self.assertNotIn("pipeline", vars(client))

    def test_clients_sharing_a_pool_keep_independent_counters(self):
        """Instrumentation must never attach to the class or connection pool."""
        client = redis.Redis()
        other = redis.Redis(connection_pool=client.connection_pool)
        with patch.object(client, "execute_command", return_value={"one"}):
            with patch.object(other, "execute_command", return_value={"two", "three"}):
                with ExitStack() as cleanup:
                    first = SearchDiagnostics(cleanup)
                    second = SearchDiagnostics(cleanup)
                    first.instrument(client)
                    second.instrument(other)
                    client.smembers("secret")
                    other.smembers("secret")
                    self.assertEqual(
                        first.kvrocks["commands"]["SMEMBERS"]["reply_items"], 1
                    )
                    self.assertEqual(
                        second.kvrocks["commands"]["SMEMBERS"]["reply_items"], 2
                    )


if __name__ == "__main__":
    unittest.main()
