"""
Generic utils library
"""

import uuid
import ipaddress
import re


def is_valid_uuid(value):
    """
    Validate a UID format
    """
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def is_valid_fqdn(hostname):
    """
    Validate a fully qualified domain name (FQDN).
    Only the Form do not test it.
    Need a "big" list of common tld.... one day.
    """
    if len(hostname) > 253:
        return False

    # Remove trailing dot if present
    if hostname.endswith("."):
        hostname = hostname[:-1]

    # Regex for valid FQDN
    fqdn_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    )
    return bool(fqdn_regex.match(hostname))


def is_valid_ip(value):
    """
    Validate an IP only public ones
    """
    try:
        ip_obj = ipaddress.ip_address(value)
        if ip_obj.is_private:
            return False
        return True
    except ValueError:
        return False


def is_valid_cidr(value):
    """
    Validate a CIDR (IPv4 or IPv6) also only public
    """
    try:
        net = ipaddress.ip_network(value, strict=False)
        # Exclude private networks
        if net.is_private:
            return False
        return True
    except ValueError:
        return False


def is_valid_ip_or_cidr(value: str):
    """
    Validate an IP or CIDR.
    Returns the normalized IP or network string if public, else False.
    """
    try:
        # try as IP
        ip_obj = ipaddress.ip_address(value)
        if ip_obj.is_private:
            return False
        return str(ip_obj)
    except ValueError:
        pass

    try:
        # try as network (CIDR)
        net = ipaddress.ip_network(value, strict=False)
        if net.is_private:
            return False
        return str(net)
    except ValueError:
        return False


def get_country(value):
    """
    GeoIP
    #TODO the Code
    """
    _ = value
    return "WW"


def flat_marsh_error(err_msg):
    """
    Flatten a Marshmallow error validation message
    """
    for key, value in err_msg.items():
        if isinstance(value, list) and len(value) > 0:
            return f"{value[0]} in {key}"


def package_list(source, size):
    """
    return chunk of lists
    """
    return [source[i : i + size] for i in range(0, len(source), size)]
