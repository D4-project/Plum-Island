"""Classify normal parser exclusions without hiding unavailable source data."""

import ipaddress

from app.utils.result_parser import is_external_ip


class ExcludedSource(ValueError):
    """A valid source address is outside the frozen parser's indexing scope."""


class SourceDocuments:
    """Keep Meilisearch retrieval unchanged and identify non-public addresses."""

    def __init__(self, index):
        self.index = index

    def get_documents(self, options):
        """Inventory every source ID; the worker records exclusions explicitly."""
        return self.index.get_documents(options)

    def get_document(self, uid):
        """Missing documents and malformed source addresses remain failures."""
        source = self.index.get_document(uid)
        document = source if isinstance(source, dict) else vars(source)
        address = str(document.get("ip") or "").strip()
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return source
        if not is_external_ip(address):
            raise ExcludedSource("Source address is excluded by the frozen parser")
        return source
