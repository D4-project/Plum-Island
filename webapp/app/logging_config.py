"""Application logging configuration and date-named file retention."""

import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE_RE = re.compile(r"^(?P<prefix>.+)-(?P<date>\d{6})\.log$")
DEFAULT_LOG_DIR = "./log"
DEFAULT_LOG_PREFIX = "agent"
DEFAULT_LOG_LEVEL = "DEBUG"
DEFAULT_LOG_ROTATION_DAYS = 90
DEFAULT_LOG_RETENTION_DAYS = 90


class DateFileHandler(logging.Handler):
    """Write logs to date-named files and remove files past retention."""

    def __init__(self, log_dir, prefix, rotation_days, retention_days):
        super().__init__()
        self.log_dir = Path(log_dir)
        self.prefix = prefix
        # Kept in the constructor for compatibility with existing config.py
        # files. Date-named application logs always rotate at local midnight.
        self.rotation_days = rotation_days
        self.retention_days = retention_days
        self._stream = None
        self._path = None
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _file_path(self, now):
        return self.log_dir / f"{self.prefix}-{now:%y%m%d}.log"

    def _needs_rotation(self, now):
        return self._stream is None or self._path != self._file_path(now)

    def _open_stream(self, now):
        if self._needs_rotation(now):
            if self._stream is not None:
                self._stream.close()
            self._path = self._file_path(now)
            self._stream = self._path.open("a", encoding="utf-8")
        return self._stream

    def _prune_old_files(self, now):
        cutoff_date = (now - timedelta(days=self.retention_days)).date()
        for path in self.log_dir.glob(f"{self.prefix}-*.log"):
            if path == self._path or not path.is_file():
                continue
            try:
                match = LOG_FILE_RE.match(path.name)
                if not match or match.group("prefix") != self.prefix:
                    continue
                file_date = datetime.strptime(match.group("date"), "%y%m%d").date()
                if file_date < cutoff_date:
                    path.unlink()
            except ValueError:
                continue
            except OSError:
                self.handleError(None)

    def emit(self, record):
        now = datetime.now()
        try:
            stream = self._open_stream(now)
            stream.write(self.format(record) + os.linesep)
            stream.flush()
            self._prune_old_files(now)
        except OSError:
            self.handleError(record)

    def close(self):
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        super().close()


def _get_positive_int(config, name, default):
    """Read a positive integer logging setting with a safe fallback."""
    try:
        value = int(config.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def configure_logging(config):
    """Configure root logging from application config values."""
    level_name = str(config.get("LOG_LEVEL", DEFAULT_LOG_LEVEL)).upper()
    level = getattr(logging, level_name, logging.DEBUG)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if not config.get("LOG_ENABLED", False):
        return None

    log_dir = config.get("LOG_DIR", DEFAULT_LOG_DIR)
    prefix = config.get("LOG_FILE_PREFIX", DEFAULT_LOG_PREFIX)
    rotation_days = _get_positive_int(
        config, "LOG_ROTATION_DAYS", DEFAULT_LOG_ROTATION_DAYS
    )
    retention_days = _get_positive_int(
        config, "LOG_RETENTION_DAYS", DEFAULT_LOG_RETENTION_DAYS
    )

    for handler in root_logger.handlers:
        if isinstance(handler, DateFileHandler):
            return handler

    handler = DateFileHandler(log_dir, prefix, rotation_days, retention_days)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s:%(levelname)s:%(name)s:%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root_logger.addHandler(handler)
    return handler
