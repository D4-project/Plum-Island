#!/usr/bin/env python3
"""Tests for application file logging."""

import logging
import io
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest import TestCase, mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.logging_config import (  # pylint: disable=wrong-import-position
    DateFileHandler,
    configure_logging,
)


class ApplicationLoggingTest(TestCase):
    """Tests for configurable persistent application logs."""

    def setUp(self):
        """Restore the operator-independent test process's root level afterwards."""
        root = logging.getLogger()
        self.addCleanup(root.setLevel, root.level)

    def test_configured_levels_filter_console_without_file_logging(self):
        """Each configured standard level controls emitted root messages."""
        for name in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            with self.subTest(level=name):
                root = logging.Logger("isolated-root")
                output = io.StringIO()
                handler = logging.StreamHandler(output)
                root.addHandler(handler)
                with mock.patch(
                    "app.logging_config.logging.getLogger", return_value=root
                ):
                    self.assertIsNone(
                        configure_logging({"LOG_LEVEL": f" {name.lower()} "})
                    )
                for message_level in (10, 20, 30, 40, 50):
                    root.log(message_level, "severity %s", message_level)
                expected = [
                    f"severity {level}"
                    for level in (10, 20, 30, 40, 50)
                    if level >= getattr(logging, name)
                ]
                self.assertEqual(output.getvalue().splitlines(), expected)
                self.assertEqual(root.handlers, [handler])

    def test_missing_or_invalid_level_falls_back_to_warning(self):
        """Missing names and non-level module attributes must neither crash nor debug."""
        configs = [{}] + [
            {"LOG_LEVEL": value}
            for value in ("INVALID", "BASIC_FORMAT", "NOTSET", "", None, True, 10)
        ]
        for config in configs:
            with self.subTest(config=config):
                root = logging.Logger("isolated-root")
                with mock.patch(
                    "app.logging_config.logging.getLogger", return_value=root
                ):
                    self.assertIsNone(configure_logging(config))
                self.assertEqual(root.level, logging.WARNING)
                self.assertEqual(root.handlers, [])

    def test_file_handler_uses_and_refreshes_configured_level(self):
        """Repeated configuration reuses its file handler and applies the new level."""
        with tempfile.TemporaryDirectory() as directory:
            root = logging.Logger("isolated-root")
            # Its own manager makes setLevel invalidate this isolated root's cache.
            root.manager = logging.Manager(root)
            config = {"LOG_ENABLED": True, "LOG_DIR": directory, "LOG_LEVEL": "INFO"}
            with mock.patch("app.logging_config.logging.getLogger", return_value=root):
                handler = configure_logging(config)
                self.addCleanup(handler.close)
                root.debug("hidden")
                root.info("visible")
                self.assertIs(
                    configure_logging(dict(config, LOG_LEVEL="DEBUG")), handler
                )
                root.debug("debug enabled")
            self.assertEqual(root.handlers, [handler])
            self.assertEqual(handler.level, logging.DEBUG)
            contents = next(Path(directory).glob("*.log")).read_text(encoding="utf-8")
            self.assertNotIn("hidden", contents)
            self.assertIn("visible", contents)
            self.assertIn("debug enabled", contents)

    def test_handler_creates_date_named_file(self):
        """First record creates the configured date-named log file."""
        with tempfile.TemporaryDirectory() as directory:
            handler = DateFileHandler(directory, "agent", 90, 90)
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger = logging.getLogger("logging-test-date")
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
            try:
                logger.info("hello")
            finally:
                logger.removeHandler(handler)
                handler.close()

            expected = Path(directory) / f"agent-{datetime.now():%y%m%d}.log"
            self.assertEqual(expected.read_text(encoding="utf-8"), "hello\n")

    def test_handler_rotates_at_midnight_in_same_process(self):
        """A long-running process writes exactly one file per calendar day."""
        first_day = datetime(2026, 9, 7, 23, 59, 59)
        second_day = datetime(2026, 9, 8, 0, 0, 1)
        with tempfile.TemporaryDirectory() as directory:
            handler = DateFileHandler(directory, "agent", 90, 90)
            handler.setFormatter(logging.Formatter("%(message)s"))
            record = logging.LogRecord("test", logging.INFO, "", 0, "entry", (), None)

            with mock.patch("app.logging_config.datetime") as clock:
                clock.now.side_effect = [first_day, second_day]
                clock.strptime.side_effect = datetime.strptime
                handler.emit(record)
                handler.emit(record)
            handler.close()

            log_dir = Path(directory)
            self.assertEqual(
                (log_dir / "agent-260907.log").read_text(encoding="utf-8"),
                "entry\n",
            )
            self.assertEqual(
                (log_dir / "agent-260908.log").read_text(encoding="utf-8"),
                "entry\n",
            )

    def test_restart_never_reuses_previous_day_file(self):
        """A fresh handler ignores a recently modified older daily log."""
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)
            previous_path = log_dir / "agent-260907.log"
            previous_path.write_text("previous\n", encoding="utf-8")

            handler = DateFileHandler(directory, "agent", 90, 90)
            handler.setFormatter(logging.Formatter("%(message)s"))
            today = datetime(2026, 9, 8, 7, 44)
            with mock.patch("app.logging_config.datetime") as clock:
                clock.now.return_value = today
                clock.strptime.side_effect = datetime.strptime
                handler.emit(
                    logging.LogRecord("test", logging.INFO, "", 0, "today", (), None)
                )
            handler.close()

            self.assertEqual(
                previous_path.read_text(encoding="utf-8"),
                "previous\n",
            )
            self.assertEqual(
                (log_dir / "agent-260908.log").read_text(encoding="utf-8"),
                "today\n",
            )

    def test_handler_prunes_files_older_than_retention(self):
        """Retention follows the date in the filename, not mutable mtime."""
        with tempfile.TemporaryDirectory() as directory:
            old_path = Path(directory) / "agent-240101.log"
            old_path.write_text("old\n", encoding="utf-8")
            recent_time = datetime.now().timestamp()
            os.utime(old_path, (recent_time, recent_time))

            handler = DateFileHandler(directory, "agent", 90, 90)
            handler.emit(
                logging.LogRecord("test", logging.INFO, "", 0, "new", (), None)
            )
            handler.close()

            self.assertFalse(old_path.exists())

    def test_disabled_config_does_not_add_file_handler(self):
        """Disabled logging leaves root handlers unchanged."""
        root = logging.getLogger()
        before = list(root.handlers)
        self.assertIsNone(configure_logging({"LOG_ENABLED": False}))
        self.assertEqual(root.handlers, before)
