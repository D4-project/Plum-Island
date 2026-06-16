"""Logging helpers shared by tools."""

import logging
import logging.handlers
from pathlib import Path

from rich.logging import RichHandler

LOGGER_NAME = "Plum_Agent"


def get_logger(name=LOGGER_NAME):
    """Return the shared Plum tool logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    return logger


def setup_logger(log_path: str | Path, debug=False, logger=None):
    """Configure Rich console logging and a persistent daily-rotated log file."""
    logger = logger or get_logger()
    if logger.handlers:
        return logger

    console_handler = RichHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    log_path = Path(log_path)
    log_path.parent.mkdir(exist_ok=True)
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=14,
        encoding="utf-8",
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="[%X]")
    )
    logger.addHandler(file_handler)
    return logger
