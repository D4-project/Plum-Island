"""
Generic utils library
"""

import uuid
import ipaddress


def is_valid_uuid(value):
    """
    Validate a UID format
    """
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def is_valid_ip(value):
    """
    Validate an IP
    """
    try:
        ip_obj = ipaddress.ip_address(value)
        if ip_obj.is_private:
            return False
        return True
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
