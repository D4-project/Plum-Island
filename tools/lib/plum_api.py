"""Plum API helpers shared by tools."""

import ipaddress
import time
from urllib.parse import urlparse

import requests

from .tool_logging import get_logger

MAX_API_ERROR_LOG_BYTES = 500
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 3
LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}

logger = get_logger()


def get_access_token(base_url: str, username: str, password: str) -> str:
    """Authenticate against Plum and return a bearer token."""
    login_url = f"{base_url}/api/v1/security/login"
    login_payload = {"username": username, "password": password, "provider": "db"}

    login_response = requests.post(login_url, json=login_payload, timeout=10)
    login_response.raise_for_status()

    return login_response.json()["access_token"]


def bulk_import_targets(base_url: str, access_token: str, bulk_payload: str) -> dict:
    """Call the bulk_import endpoint with the given access token and bulk payload."""
    bulk_import_url = f"{base_url}/targets_api/bulk_import"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {"bulk": bulk_payload}

    attempts = 0
    while True:
        try:
            response = requests.post(
                bulk_import_url,
                headers=headers,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as err:
            status_code = err.response.status_code if err.response is not None else None
            if status_code == 500 and attempts < MAX_RETRIES:
                attempts += 1
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise
        except (
            TimeoutError,
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ):
            if attempts < MAX_RETRIES:
                attempts += 1
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise


def create_target(base_url, access_token, value, description):
    """Create one Plum target, retry transient failures, and skip duplicates."""
    target_url = f"{base_url}/api/v1/publictargetsapi/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "value": value,
        "description": description[:256],
        "active": True,
    }

    attempts = 0
    while True:
        try:
            response = requests.post(
                target_url,
                headers=headers,
                json=payload,
                timeout=10,
            )
            if (
                response.status_code in (400, 409, 422)
                and "already" in response.text.lower()
            ):
                logger.debug("Target already exists: %s", value)
                return None
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as error:
            status_code = (
                error.response.status_code if error.response is not None else None
            )
            if status_code in (400, 409, 422):
                logger.warning("Target import skipped %s: %s", value, api_error(error))
                return None
            if status_code == 500 and attempts < MAX_RETRIES:
                attempts += 1
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise
        except (
            TimeoutError,
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ):
            if attempts < MAX_RETRIES:
                attempts += 1
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            raise


def api_error(error):
    """Return a bounded API error string safe for logs."""
    if error.response is None:
        return str(error)

    text = error.response.text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > MAX_API_ERROR_LOG_BYTES:
        text = f"{text[:MAX_API_ERROR_LOG_BYTES]}..."
    return f"HTTP {error.response.status_code}: {text}"


def validate_base_url(base_url):
    """Reject unsafe API base URLs before credentials are sent."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be an absolute http(s) URL")
    if parsed.scheme == "https":
        return

    hostname = parsed.hostname or ""
    if hostname.lower() in LOCAL_HTTP_HOSTS:
        return

    try:
        if ipaddress.ip_address(hostname).is_loopback:
            return
    except ValueError:
        pass

    raise ValueError("Refuse to send Plum credentials over HTTP except localhost")
