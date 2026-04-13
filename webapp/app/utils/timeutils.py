"""
Helpers for database-safe UTC timestamps.
"""

from datetime import datetime, timezone


def utcnow_aware():
    """
    Return current UTC time as an aware datetime.
    """
    return datetime.now(timezone.utc)


def utcnow_naive():
    """
    Return current UTC time as a naive datetime for SQLite DateTime columns.
    """
    return utcnow_aware().replace(tzinfo=None)


def utcnow_iso():
    """
    Return current UTC time as an RFC3339/ISO-8601 string with Z suffix.
    """
    return utcnow_aware().isoformat().replace("+00:00", "Z")


def ensure_utc_naive(value):
    """
    Normalize either aware or naive datetimes to naive UTC.
    """
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)
