"""Retry transport failures without hiding invalid data or authentication errors."""

import random
import redis
from requests import exceptions as requests_errors
from meilisearch.errors import (
    MeilisearchApiError,
    MeilisearchCommunicationError,
    MeilisearchTimeoutError,
)

TRANSIENT = (
    redis.exceptions.ConnectionError,
    redis.exceptions.TimeoutError,
    redis.exceptions.TryAgainError,
    MeilisearchCommunicationError,
    MeilisearchTimeoutError,
    requests_errors.ConnectionError,
    requests_errors.Timeout,
)


def transient_error(error):
    """A secondary reporting timeout must not mask a permanent source error."""

    def transport(item):
        if isinstance(item, redis.exceptions.AuthenticationError):
            return False
        return isinstance(item, TRANSIENT) or (
            isinstance(item, MeilisearchApiError)
            and item.status_code in (408, 429, 500, 502, 503, 504)
        )

    if not transport(error):
        return False
    seen = set()
    context = error.__cause__ or error.__context__
    while context is not None and id(context) not in seen:
        seen.add(id(context))
        if isinstance(
            context,
            (
                ValueError,
                TypeError,
                KeyError,
                redis.exceptions.ResponseError,
                redis.exceptions.AuthenticationError,
                MeilisearchApiError,
            ),
        ) and not transport(context):
            return False
        context = context.__cause__ or context.__context__
    return True


def retry_delay(attempt):
    """Back off from about 30 seconds to at most five minutes, with jitter."""
    base = min(300, 30 * 2 ** min(max(attempt - 1, 0), 4))
    return min(300, base * random.uniform(0.8, 1.2))
