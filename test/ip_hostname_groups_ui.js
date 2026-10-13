'use strict';
const assert = require('node:assert/strict');
const {createCache} = require('../webapp/app/static/js/ip_hostname_groups.js');

(async function () {
    const requests = [];
    const resolvers = new Map();
    const displayed = [];
    const states = [];
    const controller = createCache('', 'IP', key => {
        requests.push(key);
        return new Promise((resolve, reject) => resolvers.set(key, {resolve, reject}));
    }, value => displayed.push(value), state => states.push(state));
    const first = controller.select('a');
    const second = controller.select('b');
    await Promise.resolve();
    resolvers.get('b').resolve('B');
    await second;
    assert.deepEqual(displayed, ['B']);
    resolvers.get('a').resolve('A');
    await first;
    assert.deepEqual(displayed, ['B'], 'late A must not replace B');
    await controller.select('a');
    await controller.select('');
    await controller.select('b');
    assert.deepEqual(displayed, ['B', 'A', 'IP', 'B']);
    assert.deepEqual(requests, ['a', 'b'], 'back/return must use memory cache');

    const third = controller.select('c');
    const repeated = controller.select('c');
    await Promise.resolve();
    assert.deepEqual(requests, ['a', 'b', 'c'], 'share in-flight request');
    await controller.select('a');
    resolvers.get('c').reject(new Error('offline'));
    await Promise.all([third, repeated]);
    assert.equal(states.at(-1), 'ready', 'obsolete error must not affect selection');
    const retry = controller.select('c');
    await Promise.resolve();
    resolvers.get('c').resolve('C');
    await retry;
    assert.equal(displayed.at(-1), 'C');
    assert.deepEqual(requests, ['a', 'b', 'c', 'c'], 'failed requests remain retryable');
    const failure = controller.select('d');
    await Promise.resolve();
    resolvers.get('d').reject(new Error('offline'));
    await failure;
    assert.equal(states.at(-1), 'error');
    // Exercise the actual template's lazy, independent enrichment requests.
    const source = require('node:fs').readFileSync(
        require('node:path').join(__dirname, '../webapp/app/templates/ip_detail.html'), 'utf8');
    const start = source.indexOf('    function loadInformation() {');
    const end = source.indexOf('\n    function copyIpToClipboard', start);
    const element = () => ({style: {display: 'none'}, textContent: '', appendChild() {}});
    const loadingEl = element(), pdnsLoadingEl = element(), errorEl = element(), pdnsErrorEl = element();
    const enrichment = new Map();
    const context = {
        ip: '2001:db8::1', informationStarted: false,
        loadingEl, pdnsLoadingEl, errorEl, pdnsErrorEl,
        resultsEl: element(), pdnsResultsEl: element(),
        renderEntry: value => value,
        fetch: url => new Promise((resolve, reject) => enrichment.set(url, {resolve, reject}))
    };
    const vm = require('node:vm');
    vm.createContext(context);
    vm.runInContext(source.slice(start, end), context);
    assert.equal(enrichment.size, 0, 'no requests before opening Informations');
    context.loadInformation();
    assert.equal(enrichment.size, 2, 'start geo and PDNS without waiting for either');
    assert.equal(loadingEl.style.display, '');
    assert.equal(pdnsLoadingEl.style.display, '');
    context.loadInformation();
    assert.equal(enrichment.size, 2);
    enrichment.get('/ip/geolookup/2001%3Adb8%3A%3A1').resolve({ok: true, json: async () => []});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(loadingEl.style.display, 'none', 'geo completes independently');
    assert.equal(pdnsLoadingEl.style.display, '', 'PDNS spinner remains while pending');
    enrichment.get('/ip/pdns/2001%3Adb8%3A%3A1').reject(new Error('PDNS unavailable'));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(pdnsLoadingEl.style.display, 'none');
    assert.equal(pdnsErrorEl.textContent, 'PDNS unavailable');
    assert.equal(errorEl.style.display, 'none', 'PDNS failure does not fail geo');
    console.log('Hostname group cache checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
