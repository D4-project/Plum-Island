"""Opt-in, request-local search measurements; never retain keys or result data."""

import shlex
import time
from contextlib import ExitStack
from functools import wraps


def debug_requested(query):
    """Recognize a standalone directive, leaving quoted field values untouched."""
    try:
        return any(part.lower() == "debug" for part in shlex.split(query or ""))
    except ValueError:
        return False  # The query parser reports malformed quoting.


def profile_search_page(function):
    """Attach measurements only to explicitly requested interactive pages."""

    @wraps(function)
    def measured(self, query, *args, **kwargs):
        if not debug_requested(query):
            return function(self, query, *args, **kwargs)
        with ExitStack() as cleanup:
            diagnostics = SearchDiagnostics(cleanup)
            response = function(self, query, *args, _diagnostics=diagnostics, **kwargs)
            diagnostics.checkpoint("response")
            response["debug"] = diagnostics.report()
            return response

    return measured


class SearchDiagnostics:
    """Measure application stages and client calls without changing their order."""

    def __init__(self, cleanup):
        self.cleanup = cleanup
        self.started = time.perf_counter()
        self.previous = self.started
        self.stages = {}
        self.counts = {}
        self.window = {}
        self.kvrocks = {
            "commands": {},
            "direct_ms": 0.0,
            "pipeline_ms": 0.0,
            "pipeline_executions": 0,
            "max_pipeline_commands": 0,
        }

    def checkpoint(self, name):
        """End one sequential, inclusive stage using a monotonic clock."""
        now = time.perf_counter()
        self.stages[name] = (now - self.previous) * 1000
        self.previous = now

    def _replace(self, target, name, replacement):
        # Restore even on exceptions. Never patch the class or a shared pool.
        if name in vars(target):
            self.cleanup.callback(setattr, target, name, vars(target)[name])
        else:
            self.cleanup.callback(delattr, target, name)
        setattr(target, name, replacement)

    def _command(self, command, result, pipelined, elapsed_ms=0.0):
        name = command.decode() if isinstance(command, bytes) else str(command)
        name = name.upper()
        stats = self.kvrocks["commands"].setdefault(
            name,
            {
                "direct_calls": 0,
                "pipeline_calls": 0,
                "direct_ms": 0.0,
                "max_direct_ms": 0.0,
                "reply_items": 0,
                "max_reply_items": 0,
            },
        )
        stats["pipeline_calls" if pipelined else "direct_calls"] += 1
        stats["direct_ms"] += elapsed_ms
        stats["max_direct_ms"] = max(stats["max_direct_ms"], elapsed_ms)
        if name == "SCAN" and isinstance(result, (tuple, list)):
            result = result[1]
        if isinstance(result, (set, list, tuple, dict)):
            size = len(result)
        else:
            size = int(result is not None)
        stats["reply_items"] += size
        stats["max_reply_items"] = max(stats["max_reply_items"], size)

    def instrument(self, client):
        """Wrap this request's client; SCAN iterations use execute_command too."""
        execute_command = client.execute_command
        pipeline_factory = client.pipeline

        def execute(*args, **kwargs):
            started = time.perf_counter()
            result = execute_command(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - started) * 1000
            self.kvrocks["direct_ms"] += elapsed_ms
            self._command(args[0], result, False, elapsed_ms)
            return result

        def pipeline(*args, **kwargs):
            pipe = pipeline_factory(*args, **kwargs)
            original_execute = pipe.execute

            def execute_pipeline(*execute_args, **execute_kwargs):
                # redis-py replaces this list on reset; retain its existing reference.
                commands = pipe.command_stack
                started = time.perf_counter()
                results = original_execute(*execute_args, **execute_kwargs)
                self.kvrocks["pipeline_ms"] += (time.perf_counter() - started) * 1000
                self.kvrocks["pipeline_executions"] += 1
                self.kvrocks["max_pipeline_commands"] = max(
                    self.kvrocks["max_pipeline_commands"], len(commands)
                )
                for (command_args, _options), result in zip(commands, results):
                    self._command(command_args[0], result, True)
                return results

            # Pipeline is local and short-lived: no cleanup reference retaining it.
            pipe.execute = execute_pipeline
            return pipe

        self._replace(client, "execute_command", execute)
        self._replace(client, "pipeline", pipeline)

    def report(self):
        """Return aggregates only; client durations include waiting and decoding."""
        return {
            "schema_version": 1,
            "total_ms": (time.perf_counter() - self.started) * 1000,
            "stages_ms": self.stages,
            "counts": self.counts,
            "window": self.window,
            "kvrocks": self.kvrocks,
        }
