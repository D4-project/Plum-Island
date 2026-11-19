"""DNS and target-address helpers shared by tools."""

import concurrent.futures
import ipaddress
import socket

from .tool_logging import get_logger


def is_ip_or_cidr(entry: str) -> bool:
    """Return True when the target is an IP address or CIDR network."""
    try:
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def is_ipv4_address(label: str) -> bool:
    """Return True when the label is an IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(label), ipaddress.IPv4Address)
    except ValueError:
        return False


def resolve_single_fqdn(fqdn: str):
    """Resolve a single FQDN using socket.getaddrinfo."""
    try:
        infos = socket.getaddrinfo(fqdn, None)
    except socket.gaierror as exc:
        return [], str(exc)
    except TimeoutError as exc:  # pragma: no cover - defensive
        return [], str(exc)

    addresses = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addresses.append(sockaddr[0])
    return sorted(set(addresses)), None


def resolve_fqdn(fqdn: str) -> list[str]:
    """Resolve an FQDN and return unique IP addresses."""
    addresses, _ = resolve_single_fqdn(fqdn)
    return addresses


def resolve_fqdns(fqdns, workers=25, progress_interval=100, logger=None):
    """Resolve a list of FQDNs concurrently using socket.getaddrinfo."""
    logger = logger or get_logger()
    results = {}
    total = len(fqdns)
    resolved_count = 0
    failed_count = 0
    logger.info("Resolve FQDN count: %d", total)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(resolve_single_fqdn, fqdn): fqdn for fqdn in fqdns
        }
        for processed_count, future in enumerate(
            concurrent.futures.as_completed(future_map), start=1
        ):
            fqdn = future_map[future]
            try:
                addresses, error = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                addresses, error = [], str(exc)
                logger.debug("FQDN resolve worker failed for %s: %s", fqdn, exc)
            if addresses:
                resolved_count += 1
                logger.debug("Resolve success %s -> %s", fqdn, ", ".join(addresses))
            else:
                failed_count += 1
                logger.debug("Resolve failed %s: %s", fqdn, error or "no answer")
            results[fqdn] = {"addresses": addresses, "error": error}
            if processed_count % progress_interval == 0:
                logger.info(
                    "Resolve progress: %d/%d resolved=%d failed=%d",
                    processed_count,
                    total,
                    resolved_count,
                    failed_count,
                )
    logger.info(
        "Resolve complete: %d/%d resolved=%d failed=%d",
        total,
        total,
        resolved_count,
        failed_count,
    )
    return results


def count_resolved(resolutions):
    """Count FQDNs with at least one resolved address."""
    if not resolutions:
        return 0
    return sum(1 for data in resolutions.values() if data.get("addresses"))
