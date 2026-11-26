/* Exercise the actual progress controller without backend or browser dependencies. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const status = {textContent: ''};
const eta = {textContent: ''};
const detail = {textContent: ''};
const attributes = {};
const classes = new Set();
const bar = {
    style: {}, textContent: '',
    setAttribute: (key, value) => { attributes[key] = value; },
    removeAttribute: key => { delete attributes[key]; },
    classList: {toggle: (key, value) => value ? classes.add(key) : classes.delete(key)}
};
const root = {
    dataset: {statusUrl: '/tagrulesview/reindex_current'},
    querySelector: key => ({'[data-index-status]': status,
        '[data-index-eta]': eta,
        '[data-index-progress]': bar, '[data-index-detail]': detail})[key]
};
let state = {phase: 'planning', processed: 0, total: null};
let next;
let requests = 0;
const context = vm.createContext({
    document: {querySelector: () => root},
    fetch: async (url, options) => {
        requests += 1;
        assert.equal(url, root.dataset.statusUrl);
        assert.equal(options.method, undefined); // Status GET never starts work.
        return {ok: true, json: async () => state};
    },
    window: {setTimeout: callback => { next = callback; }}
});
vm.runInContext(fs.readFileSync(path.join(__dirname,
    '../webapp/app/static/js/tag_reconciliation.js'), 'utf8'), context);

async function advance(value) {
    state = value;
    await next();
}

(async () => {
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(attributes['aria-valuenow'], undefined);
    assert.match(status.textContent, /Identifying/);
    assert.match(eta.textContent, /Calculating/);
    await advance({phase: 'reparsing', processed: 64, total: 100, pending_changes: 3,
        pacing: {mode: 'idle_boost', eta_seconds: 3900}});
    assert.equal(bar.style.width, '64%');
    assert.equal(attributes['aria-valuenow'], '64');
    assert.match(detail.textContent, /3 additional/);
    assert.match(detail.textContent, /Full Indexing/);
    assert.match(eta.textContent, /ETA 1h 5m/);
    await advance({phase: 'paused', processed: 64, total: 100, pacing: {eta_seconds: 3900}});
    assert.equal(bar.style.width, '64%');
    assert.match(detail.textContent, /64\/100 captures/);
    assert.match(eta.textContent, /ETA ∞/);
    await advance({phase: 'reparsing', processed: 64, total: 100, heartbeat: 1,
        pacing: {mode: 'idle_boost', eta_seconds: 3900}});
    assert.match(eta.textContent, /ETA ∞/);
    await advance({phase: 'catching_up', processed: 100, total: null});
    assert.equal(attributes['aria-valuenow'], undefined);
    await advance({phase: 'blocked', message: '<img src=x onerror=alert(1)>'});
    assert.equal(detail.textContent, '<img src=x onerror=alert(1)>');
    assert(classes.has('progress-bar-danger'));
    assert(!classes.has('active'));
    await advance({phase: 'planning', pacing: {mode: 'foreground'}});
    assert.equal(detail.textContent, 'Indexing paused for searches and imports');
    assert.match(eta.textContent, /ETA ∞/);
    await advance({phase: 'planning', pacing: {mode: 'idle_boost', candidates: 1234}});
    assert.match(detail.textContent, /Fast Indexing/);
    assert.match(detail.textContent, /1234 captures identified/);
    assert(!detail.textContent.includes('%'));
    await advance({phase: 'planning', pacing: {mode: 'limited', slowdown_factor: 2, comparable_samples: 4, observed_degradation: 0.71}});
    assert.equal(detail.textContent, 'Fast Indexing slowed down to protect search performance');
    await advance({phase: 'reparsing', pacing: {mode: 'limited', slowdown_factor: 2}});
    assert.equal(detail.textContent, 'Full Indexing slowed down to protect search performance');
    // Idle acceleration can still be throttled; the effective factor wins.
    await advance({phase: 'retagging', pacing: {mode: 'idle_boost', slowdown_factor: 2}});
    assert.equal(detail.textContent, 'Fast Indexing slowed down to protect search performance');
    await advance({phase: 'retagging', pacing: {mode: 'idle_boost', slowdown_factor: 2, uses_meilisearch: true}});
    assert.equal(detail.textContent, 'Full Indexing slowed down to protect search performance');
    // A retained timing sample must not label recovered idle throughput as slow.
    await advance({phase: 'retagging', pacing: {mode: 'idle_boost', slowdown_factor: 1, comparable_samples: 4, observed_degradation: 0.71}});
    assert.equal(detail.textContent, 'Fast Indexing');
    // A mixed job can reach a Kvrocks-only batch after having read Meilisearch.
    await advance({phase: 'retagging', pacing: {mode: 'idle_boost', uses_meilisearch: true}});
    assert.equal(detail.textContent, 'Full Indexing');
    await advance({phase: 'planning', pacing: {mode: 'limited', slowdown_factor: 1}});
    assert.equal(detail.textContent, 'Indexing in the background');
    await advance({phase: 'blocked', pacing: {mode: 'idle_boost', slowdown_factor: 1}});
    assert.equal(detail.textContent, '');
    await advance({phase: 'up_to_date', pacing: {excluded_sources: 2, missing_sources: 5}});
    assert.equal(bar.style.width, '100%');
    assert.equal(status.textContent, 'Detections up to date');
    assert.match(detail.textContent, /2 non-public source exclusions encountered/);
    assert.match(detail.textContent, /5 captures awaiting a Meilisearch source/);
    assert.equal(requests, 17);
    console.log('Automatic detection progress checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
