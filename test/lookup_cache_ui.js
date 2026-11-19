'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assets = path.join(__dirname, '../webapp/app/static/js');
const helper = fs.readFileSync(path.join(assets, 'lookup_cache.js'), 'utf8');
const target = fs.readFileSync(path.join(assets, 'target_network_info.js'), 'utf8');
function element() {
  return {textContent: '', children: [], append(...nodes) { this.children.push(...nodes); },
    set innerHTML(_value) { throw new Error('Lookup data must use textContent'); }};
}
async function verify(body, ok = true, contentType = 'application/json') {
  const elements = Object.fromEntries(['target-network-cache', 'target-network-status', 'target-network-result']
    .map(id => [id, element()]));
  const context = vm.createContext({
    document: {
      querySelector: () => ({dataset: {targetNetworkUrl: '/targetsview/network_info/1'}}),
      getElementById: id => elements[id], createElement: element
    },
    fetch: async () => ({ok, headers: {get: () => contentType}, json: async () => body})
  });
  vm.runInContext('window = globalThis;', context);
  vm.runInContext(helper, context);
  vm.runInContext(target, context);
  await new Promise(resolve => setImmediate(resolve));
  return {context, elements};
}
(async () => {
  const fetchedAt = new Date(2026, 10, 19, 10, 25, 2).getTime() / 1000;
  const {context, elements} = await verify({
    info: {asn: 64500, name: '<img src=x onerror=alert(1)>', country_alpha3: 'LUX',
      country_numeric: '442', latitude: null, longitude: null},
    cache: {cached: true, fetched_at: fetchedAt, expires_at: fetchedAt + 86400}
  });
  const expected = 'Fetched 19/11/2026 at 10:25:02';
  assert.equal(elements['target-network-cache'].textContent, expected);
  context.PlumLookupCache.show('target-network-cache', {cached: false, fetched_at: fetchedAt});
  assert.equal(elements['target-network-cache'].textContent, expected);
  assert.equal(elements['target-network-result'].children[3].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(elements['target-network-status'].textContent, '');
  vm.runInContext("PlumLookupCache.show('target-network-cache', null);", context);
  assert.equal(elements['target-network-cache'].textContent, '');
  const failed = await verify({error: 'Lookup failed'}, false);
  assert.equal(failed.elements['target-network-status'].textContent, 'Lookup failed');
  const denied = await verify({}, true, 'text/html');
  assert.match(denied.elements['target-network-status'].textContent, /Sign in/);
  const disabled = await verify({disabled: true, message: 'Unavailable for FQDN targets'});
  assert.match(disabled.elements['target-network-status'].textContent, /FQDN/);
})().catch(error => { console.error(error); process.exitCode = 1; });
