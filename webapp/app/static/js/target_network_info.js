(function () {
  'use strict';
  const panel = document.querySelector('[data-target-network-url]');
  if (!panel) return;
  const status = document.getElementById('target-network-status');
  const output = document.getElementById('target-network-result');
  fetch(panel.dataset.targetNetworkUrl, {credentials: 'same-origin', headers: {Accept: 'application/json'}})
    .then(async function (response) {
      if (!(response.headers.get('content-type') || '').includes('application/json')) {
        throw new Error('IP and AS information unavailable. Sign in and retry.');
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'IP and AS lookup failed.');
      if (data.disabled) { status.textContent = data.message; return; }
      status.textContent = '';
      PlumLookupCache.show('target-network-cache', data.cache);
      [['asn', 'ASN'], ['name', 'AS name'], ['country_alpha3', 'Country alpha-3'],
        ['country_numeric', 'Country numeric code'], ['latitude', 'Latitude (country average)'],
        ['longitude', 'Longitude (country average)']].forEach(function (field) {
        const label = document.createElement('dt');
        const value = document.createElement('dd');
        label.textContent = field[1];
        const raw = data.info[field[0]];
        value.textContent = raw === null ? 'Unavailable' : field[0] === 'asn' ?
          (raw === 0 ? 'CIDR not announced' : 'AS' + raw) : String(raw);
        output.append(label, value);
      });
    }).catch(function (error) { status.textContent = error.message; });
}());
