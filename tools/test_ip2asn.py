#!/usr/bin/env python3
"""
Regression tests for IP to ASN helpers.
"""

import os
import sys
from unittest import TestCase, main

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "webapp", "app", "utils")
)

import ip2asn  # pylint: disable=wrong-import-position,import-error

INVALID_NETWORK_MESSAGE = ip2asn.INVALID_NETWORK_MESSAGE
get_asn_description_for_ip = ip2asn.get_asn_description_for_ip


class IP2ASNTest(TestCase):
    """Tests for defensive IP to ASN behavior."""

    def test_fqdn_does_not_raise_addr_format_error(self):
        """FQDN targets should not be passed to netaddr as IP networks."""
        self.assertEqual(
            get_asn_description_for_ip("yper-i.unrwa.org"), INVALID_NETWORK_MESSAGE
        )


if __name__ == "__main__":
    main()
