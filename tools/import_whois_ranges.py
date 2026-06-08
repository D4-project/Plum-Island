#!/usr/bin/env python3
# coding=utf-8

"""
Download registry sources and print/import configured country ranges as CIDR.
"""

import argparse
import gzip
import ipaddress
import logging
import logging.handlers
import os
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

import requests
import yaml
from rich.logging import RichHandler

THIS_DIR = Path(__file__).resolve().parent
TOOLS_DIR = THIS_DIR.parent
RANGE_IMPORT_CONFIG = THIS_DIR / "range_import.yaml"
DOWNLOAD_DIR = THIS_DIR / "tmp"
DOWNLOAD_MAX_AGE_SECONDS = 24 * 60 * 60
DOWNLOAD_CHUNK_SIZE = 1024 * 1024
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_API_ERROR_LOG_BYTES = 500
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 3
DEFAULT_DESCRIPTION = "WHOIS range import"
LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}

SOURCES = [
    {
        "name": "afrinic",
        "url": "ftp://ftp.afrinic.net/pub/dbase/afrinic.db.gz",
        "enabled": True,
    },
    {
        "name": "apnic-inetnum",
        "url": "ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz",
        "enabled": True,
    },
    {
        "name": "apnic-inet6num",
        "url": "ftp://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz",
        "enabled": False,
    },
    {
        "name": "arin",
        "url": "ftp://ftp.arin.net/pub/rr/arin.db",
        "enabled": False,
    },
    {
        "name": "lacnic-delegated",
        "url": "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "enabled": True,
    },
    {
        "name": "ripe-inetnum",
        "url": "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
        "enabled": True,
    },
    {
        "name": "ripe-inet6num",
        "url": "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz",
        "enabled": False,
    },
]

sys.path.insert(0, str(TOOLS_DIR))

logger = logging.getLogger("Plum_Agent")
logger.setLevel(logging.DEBUG)


def setup_logger(debug=False):
    """Configure Rich console logging and the persistent import log file."""
    if logger.handlers:
        return

    console_handler = RichHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    log_dir = THIS_DIR / "log"
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_dir / "import_whois_ranges.log",
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


def url_filename(url):
    """Return the destination filename from a source URL."""
    parsed = urlparse(url)
    filename = os.path.basename(parsed.path)
    if not filename:
        raise ValueError(f"URL has no filename: {url}")
    return filename


def should_download(path, force_download=False):
    """Decide whether a cached source file must be downloaded again."""
    if force_download:
        return True
    if not path.exists():
        return True

    age_seconds = max(0, int(time.time() - path.stat().st_mtime))
    if age_seconds > DOWNLOAD_MAX_AGE_SECONDS:
        logger.info(
            "Download refresh, file older than 24h: %s (%ds)",
            path.name,
            age_seconds,
        )
        return True

    return False


def download(source, destination_dir, force_download=False):
    """Download one WHOIS source when the local cached copy is stale or missing."""
    url = source["url"]
    destination = destination_dir / url_filename(url)
    temporary_destination = destination.with_name(f"{destination.name}.part")
    if not should_download(destination, force_download=force_download):
        logger.info(
            "Download skip, file fresh: %s (%s)", destination.name, source["name"]
        )
        return destination

    logger.info("Download %s: %s", source["name"], url)
    try:
        with urlopen(url, timeout=120) as response:
            with temporary_destination.open("wb") as output:
                copy_response_limited(response, output)
        temporary_destination.replace(destination)
    except Exception:
        temporary_destination.unlink(missing_ok=True)
        raise

    logger.info("Downloaded %s: %s", source["name"], destination.name)
    return destination


def copy_response_limited(response, output):
    """Copy a download stream while enforcing a compressed-size limit."""
    total_bytes = 0
    while True:
        chunk = response.read(DOWNLOAD_CHUNK_SIZE)
        if not chunk:
            return

        total_bytes += len(chunk)
        if total_bytes > MAX_DOWNLOAD_BYTES:
            raise ValueError(
                f"Download exceeds {MAX_DOWNLOAD_BYTES} bytes compressed limit"
            )
        output.write(chunk)


def open_text(path):
    """Open plain text or gzip-compressed registry data as decoded text."""
    with path.open("rb") as raw:
        magic = raw.read(2)

    if magic == b"\x1f\x8b" or path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")

    return path.open("r", encoding="utf-8", errors="replace")


def cidrs_from_range(range_text):
    """Convert an inetnum start-end range into the smallest CIDR list."""
    start_text, end_text = [part.strip() for part in range_text.split("-", 1)]
    start = ipaddress.ip_address(start_text)
    end = ipaddress.ip_address(end_text)
    return [str(network) for network in ipaddress.summarize_address_range(start, end)]


def emit_cidrs(source, range_text, description):
    """Convert one registry range to CIDRs and return them with a description."""
    try:
        cidrs = cidrs_from_range(range_text)
    except ValueError as error:
        logger.warning("Invalid inetnum in %s: %s (%s)", source, range_text, error)
        return {}

    for cidr in cidrs:
        logger.debug("%s %s %s", source, cidr, description)

    return {cidr: description for cidr in cidrs}


def process_whois_file(path, country_codes, words):
    """Extract CIDRs from RIR WHOIS records matching configured countries or words."""
    found = {}
    record = []

    def flush_record():
        """Process the current WHOIS record and return matching CIDRs."""
        if not record:
            return {}

        country_match = False
        word_match = False
        inetnum = None
        netname = None

        for line in record:
            lower_line = line.lower()
            if line.lower().startswith("inetnum:") and inetnum is None:
                inetnum = line.split(":", 1)[1].strip()
            elif line.lower().startswith("netname:") and netname is None:
                netname = line.split(":", 1)[1].strip()
            elif line.lower().startswith("country:"):
                country = line.split(":", 1)[1].strip().upper()
                if country in country_codes:
                    country_match = True
            if words and any(word in lower_line for word in words):
                word_match = True

        if (country_match or word_match) and inetnum:
            return emit_cidrs(path.name, inetnum, netname or DEFAULT_DESCRIPTION)

        return {}

    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                found.update(flush_record())
                record = []
                continue
            record.append(line.rstrip("\n"))

    found.update(flush_record())
    return found


def process_lacnic_delegated(path, country_codes, words):
    """Extract IPv4 CIDRs from the LACNIC delegated stats format."""
    found = {}

    with open_text(path) as handle:
        for line in handle:
            if line.startswith("#"):
                continue

            parts = line.strip().split("|")
            if not lacnic_row_matches(parts, line, country_codes, words):
                continue

            for cidr in lacnic_row_cidrs(path, parts, line):
                cidr_text = str(cidr)
                logger.debug("%s %s %s", path.name, cidr_text, DEFAULT_DESCRIPTION)
                found[cidr_text] = DEFAULT_DESCRIPTION

    return found


def lacnic_row_matches(parts, line, country_codes, words):
    """Return whether a delegated LACNIC row matches configured filters."""
    if len(parts) < 7:
        return False

    registry, country, record_type = parts[:3]
    word_match = words and any(word in line.lower() for word in words)
    return (
        registry == "lacnic"
        and record_type == "ipv4"
        and (country.upper() in country_codes or word_match)
    )


def lacnic_row_cidrs(path, parts, line):
    """Convert a delegated LACNIC IPv4 start/count row into CIDR objects."""
    _, _, _, start, value = parts[:5]

    try:
        first_ip = ipaddress.ip_address(start)
        last_ip = ipaddress.ip_address(int(first_ip) + int(value) - 1)
    except ValueError as error:
        logger.warning("Invalid delegated row in %s: %s (%s)", path.name, line, error)
        return []

    return list(ipaddress.summarize_address_range(first_ip, last_ip))


def process_file(path, country_codes, words):
    """Dispatch a cached source file to the correct parser."""
    if path.name == "delegated-lacnic-extended-latest":
        return process_lacnic_delegated(path, country_codes, words)
    return process_whois_file(path, country_codes, words)


def reduce_ranges(ranges):
    """Remove local CIDRs already covered by a wider CIDR in the same import."""
    networks = {
        ipaddress.ip_network(cidr, strict=False): description
        for cidr, description in ranges.items()
    }
    sorted_networks = sorted(
        networks,
        key=lambda net: (net.version, int(net.network_address), net.prefixlen),
    )
    kept = []
    reduced = {}

    for network in sorted_networks:
        if any(
            network.version == kept_network.version and network.subnet_of(kept_network)
            for kept_network in kept
        ):
            logger.debug("Skip covered CIDR: %s", network)
            continue

        kept.append(network)
        reduced[str(network)] = networks[network]

    return reduced


def count_ips(ranges):
    """Return the total number of addresses represented by CIDR keys."""
    return sum(
        ipaddress.ip_network(cidr, strict=False).num_addresses for cidr in ranges.keys()
    )


def import_ranges_to_plum(ranges):
    """Authenticate to Plum and import CIDR targets through the public API."""
    config = load_range_import_config(require_credentials=True)
    base_url = config["base_url"]
    validate_base_url(base_url)
    username = config["username"]
    password = config["password"]
    token = get_access_token(base_url, username, password)

    submitted = 0
    skipped = 0
    for cidr, description in ranges.items():
        result = create_target(base_url, token, cidr, description)
        if result is None:
            skipped += 1
            continue
        submitted += 1
        logger.debug("Plum import result %s: %s", cidr, result)

    logger.info("Plum import submitted CIDR: %d", submitted)
    logger.info("Plum import skipped CIDR: %d", skipped)


def load_range_import_config(require_credentials=False):
    """Load and normalize range import configuration from YAML."""
    if not RANGE_IMPORT_CONFIG.is_file():
        raise FileNotFoundError(f"Missing config: {RANGE_IMPORT_CONFIG}")

    warn_config_permissions(RANGE_IMPORT_CONFIG)
    with RANGE_IMPORT_CONFIG.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    base_url = config.get("base_url") or config.get("PLUMISLAND")
    username = (
        config.get("username") or config.get("usernate") or config.get("PLUMAPIUSER")
    )
    password = config.get("password") or config.get("PLUMAPIPWD")
    country_codes = normalize_country_codes(config.get("country") or ["LU"])
    words = normalize_words(config.get("words") or [])

    missing = []
    if not country_codes:
        missing.append("country")
    if require_credentials:
        missing.extend(
            name
            for name, value in (
                ("base_url", base_url),
                ("username", username),
                ("password", password),
            )
            if not value
        )
    if missing:
        raise KeyError(f"Missing {', '.join(missing)} in {RANGE_IMPORT_CONFIG}")

    return {
        "base_url": base_url.rstrip("/") if base_url else "",
        "username": username or "",
        "password": password or "",
        "country": country_codes,
        "words": words,
    }


def warn_config_permissions(path):
    """Warn when the credential config is readable or writable by group/others."""
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        logger.warning(
            "Config file permissions are too open, consider chmod 600: %s", path
        )


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


def normalize_country_codes(value):
    """Normalize configured country values to uppercase ISO code strings."""
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []

    country_codes = {
        str(candidate).strip().upper()
        for candidate in candidates
        if str(candidate).strip()
    }
    return sorted(country_codes)


def normalize_words(value):
    """Normalize configured word matches to lowercase strings."""
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []

    words = {
        str(candidate).strip().lower()
        for candidate in candidates
        if str(candidate).strip()
    }
    return sorted(words)


def get_access_token(base_url, username, password):
    """Authenticate against Plum and return a bearer token."""
    login_url = f"{base_url}/api/v1/security/login"
    login_payload = {"username": username, "password": password, "provider": "db"}

    login_response = requests.post(login_url, json=login_payload, timeout=10)
    login_response.raise_for_status()

    return login_response.json()["access_token"]


def create_target(base_url, access_token, cidr, description):
    """Create one Plum target, retry transient failures, and skip duplicates."""
    target_url = f"{base_url}/api/v1/publictargetsapi/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "value": cidr,
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
                logger.debug("Target already exists: %s", cidr)
                return None
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as error:
            status_code = (
                error.response.status_code if error.response is not None else None
            )
            if status_code in (400, 409, 422):
                logger.warning("Target import skipped %s: %s", cidr, api_error(error))
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


def main():
    """Run the WHOIS range importer command-line workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--forcedownload",
        action="store_true",
        help="download sources even if cached files are newer than 24h",
    )
    parser.add_argument(
        "--debug", action="store_true", help="show debug logs on console"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="download/parse only, do not import found CIDRs into Plum",
    )
    args = parser.parse_args()

    setup_logger(debug=args.debug)
    config = load_range_import_config()
    country_codes = config["country"]
    words = config["words"]
    word_label = ",".join(words)

    sources = [source for source in SOURCES if source["enabled"]]
    if not sources:
        logger.error("No active source configured")
        return 1

    logger.info("Active sources: %d", len(sources))
    if words:
        logger.info("Words: %s", word_label)
    ranges = {}
    force_download = args.forcedownload
    DOWNLOAD_DIR.mkdir(exist_ok=True)

    for source in sources:
        path = download(source, DOWNLOAD_DIR, force_download=force_download)
        ranges.update(process_file(path, country_codes, words))

    reduced_ranges = reduce_ranges(ranges)
    logger.info("Matching CIDR count: %d", len(ranges))
    logger.info("Matching reduced CIDR count: %d", len(reduced_ranges))
    logger.info("Matching covered CIDR skipped: %d", len(ranges) - len(reduced_ranges))
    logger.info("Matching total IP count: %d", count_ips(reduced_ranges))

    if args.dry_run:
        logger.info("Dry run enabled, skip Plum import")
    else:
        import_ranges_to_plum(reduced_ranges)

    return 0


if __name__ == "__main__":
    sys.exit(main())
