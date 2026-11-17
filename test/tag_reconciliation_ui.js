/* Exercise the actual progress controller without backend or browser dependencies. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const status = {textContent: ''};
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
    await advance({phase: 'reparsing', processed: 64, total: 100, pending_changes: 3});
    assert.equal(bar.style.width, '64%');
    assert.equal(attributes['aria-valuenow'], '64');
    assert.match(detail.textContent, /3 additional/);
    await advance({phase: 'catching_up', processed: 100, total: null});
    assert.equal(attributes['aria-valuenow'], undefined);
    await advance({phase: 'blocked', message: '<img src=x onerror=alert(1)>'});
    assert.equal(detail.textContent, '<img src=x onerror=alert(1)>');
    assert(classes.has('progress-bar-danger'));
    assert(!classes.has('active'));
    await advance({phase: 'up_to_date'});
    assert.equal(bar.style.width, '100%');
    assert.equal(status.textContent, 'Detections up to date');
    assert.equal(requests, 5);
    console.log('Automatic detection progress checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
