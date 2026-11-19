/* Freshness belongs to the source response, not to the displayed observations. */
window.PlumLookupCache = {
  show: function (id, metadata) {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = '';
    if (!metadata || !Number.isFinite(Number(metadata.fetched_at))) return;
    const fetched = new Date(Number(metadata.fetched_at) * 1000);
    const expires = new Date(Number(metadata.expires_at) * 1000);
    element.textContent = (metadata.cached ? 'Cached' : 'Fresh lookup') +
      ' · Fetched ' + fetched.toLocaleString() + ' · Expires ' + expires.toLocaleString();
  },
  headers: function (response) {
    if (!response.headers.get('X-Lookup-Fetched-At')) return null;
    return {
      cached: response.headers.get('X-Lookup-Cache') === 'hit',
      fetched_at: Number(response.headers.get('X-Lookup-Fetched-At')),
      expires_at: Number(response.headers.get('X-Lookup-Expires-At'))
    };
  }
};
