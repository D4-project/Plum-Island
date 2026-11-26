"""Read reconciliation sources and classify normal parser exclusions."""

import ipaddress

from meilisearch._httprequests import HttpRequests
from meilisearch.errors import MeilisearchCommunicationError
from requests.exceptions import ChunkedEncodingError

from app.utils.result_parser import is_external_ip


class ReconciliationHttpRequests(HttpRequests):
    """Keep the SDK's request semantics with a worker-owned HTTP session."""

    def __init__(self, config, session):
        super().__init__(config)
        self.session = session

    def send_request(self, http_method, *args, **kwargs):
        """Route document GETs and inventory POSTs through the same pool."""
        method = getattr(self.session, http_method.__name__)
        try:
            return super().send_request(method, *args, **kwargs)
        except ChunkedEncodingError as error:
            # A connection lost while reading the body is also retryable.
            raise MeilisearchCommunicationError(str(error)) from error


class ExcludedSource(ValueError):
    """A valid source address is outside the frozen parser's indexing scope."""

    def __init__(self, address):
        self.address = address
        super().__init__("Source address is excluded by the frozen parser")


class SourceDocuments:
    """Read batches in candidate order and classify sources when consumed."""

    def __init__(self, index, batch_size=1):
        self.index = index
        self.batch_size = max(1, int(batch_size))
        self._candidates = ()
        self._prefetched = {}

    def get_documents(self, options):
        """Inventory every source ID; the worker records exclusions explicitly."""
        return self.index.get_documents(options)

    def use_candidates(self, candidates):
        """Keep only buffered results still in the current durable candidate list."""
        if self._candidates is candidates:
            return
        self._candidates = candidates
        remaining = self._prefetched.keys() & set(candidates)
        self._prefetched = {uid: self._prefetched[uid] for uid in remaining}

    def _prefetch(self, uid):
        """Fetch ahead only after a capture actually needs its raw source."""
        if self.batch_size == 1 or uid not in self._candidates:
            return
        start = self._candidates.index(uid)
        uids = list(dict.fromkeys(self._candidates[start : start + self.batch_size]))
        if len(uids) < 2:
            return
        page = self.index.get_documents({"ids": uids, "limit": len(uids)})
        prefetched = dict.fromkeys(uids)
        for source in page.results:
            source_uid = str(dict(source).get("id", ""))
            if source_uid in prefetched:
                prefetched[source_uid] = source
        self._prefetched = prefetched

    def get_document(self, uid):
        """Missing documents and malformed source addresses remain failures."""
        if uid not in self._prefetched:
            self._prefetch(uid)
        source = self._prefetched.pop(uid, None)
        if source is None:
            # The single-document endpoint preserves missing-source errors and
            # observes a capture inserted after the batch read.
            source = self.index.get_document(uid)
        document = source if isinstance(source, dict) else vars(source)
        address = str(document.get("ip") or "").strip()
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return source
        if not is_external_ip(address):
            raise ExcludedSource(address)
        return source
