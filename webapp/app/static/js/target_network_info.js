(function () {
  'use strict';
  const panel = document.querySelector('[data-target-network-url]');
  if (!panel) return;
  const status = document.getElementById('target-network-status');
  const output = document.getElementById('ip-info-results');

  function addInfoRow(grid, label, value) {
    if (value === null || value === undefined || value === '') return;
    const labelEl = document.createElement('div');
    labelEl.className = 'ip-info-label';
    labelEl.textContent = label;
    const valueEl = document.createElement('div');
    valueEl.className = 'ip-info-value';
    valueEl.textContent = String(value);
    grid.append(labelEl, valueEl);
  }

  function addInfoCard(titleText, rows) {
    const wrapper = document.createElement('div');
    wrapper.className = 'ip-info-entry';
    const title = document.createElement('div');
    title.className = 'ip-info-title';
    title.textContent = titleText;
    const box = document.createElement('div');
    box.className = 'ip-info-box';
    const grid = document.createElement('div');
    grid.className = 'ip-info-grid';
    rows.forEach(([label, value]) => addInfoRow(grid, label, value));
    box.appendChild(grid);
    wrapper.append(title, box);
    output.appendChild(wrapper);
  }

  function countryName(info) {
    const alpha2 = info.country_alpha2;
    if (alpha2 && typeof Intl.DisplayNames === 'function') {
      try {
        return new Intl.DisplayNames(['en'], {type: 'region'}).of(alpha2) || info.country_alpha3 || '';
      } catch (_) {
        // Fall back to the alpha-3 code if the browser cannot localize this code.
      }
    }
    return info.country_alpha3 || '';
  }

  function renderMap(info) {
    if (!window.PlumShowLocation) return;
    const country = countryName(info);
    const geoData = Promise.resolve([{
      country_info: {
        Country: country,
        'Alpha-2 code': info.country_alpha2,
        'Alpha-3 code': info.country_alpha3,
        'Numeric code': info.country_numeric,
        'Latitude (average)': info.latitude,
        'Longitude (average)': info.longitude,
      },
      country: {
        iso_code: info.country_alpha2,
        AutonomousSystemNumber: info.asn,
        AutonomousSystemOrganization: info.name,
      },
    }]);
    window.PlumShowLocation(geoData);
  }

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
      const info = data.info || {};
      const country = countryName(info);
      const asn = info.asn === 0 ? 'CIDR not announced' : info.asn ? `AS${info.asn}` : null;
      addInfoCard('IP Informations', [
        ['Country', country],
        ['ISO Code', info.country_alpha2],
        ['Alpha-3', info.country_alpha3],
        ['Numeric code', info.country_numeric],
        ['Latitude (country average)', info.latitude],
        ['Longitude (country average)', info.longitude],
      ]);
      addInfoCard('Autonomous System Informations', [
        ['ASN', asn],
        ['AS Name', info.name],
      ]);
      renderMap(info);
    }).catch(function (error) { status.textContent = error.message; });
}());
