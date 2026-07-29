#!/usr/bin/env python3
"""Tests for application file logging."""

import logging
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest import TestCase

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "webapp"))

from app.logging_config import DateFileHandler, configure_logging


class ApplicationLoggingTest(TestCase):
    """Tests for configurable persistent application logs."""

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

    def test_handler_prunes_files_older_than_retention(self):
        """Old generated files are deleted when a record is written."""
        with tempfile.TemporaryDirectory() as directory:
            old_path = Path(directory) / "agent-240101.log"
            old_path.write_text("old\n", encoding="utf-8")
            old_time = (datetime.now() - timedelta(days=91)).timestamp()
            old_path.touch()
            os.utime(old_path, (old_time, old_time))

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
