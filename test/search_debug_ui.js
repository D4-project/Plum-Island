// Execute the actual template script with a minimal DOM, without a web server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '../webapp/app/templates/search_kvrocks.html'), 'utf8');
const source = template.split('<script>')[1].split('</script>')[0];
const elements = new Map();
let clock = 10;
let downloaded;
let clicked = false;
const context = vm.createContext({
    console,
    Date,
    Blob,
    performance: {now: () => clock},
    setTimeout: () => {},
    URL: {
        createObjectURL: (blob) => { downloaded = blob; return 'blob:test'; },
        revokeObjectURL: () => {}
    },
    document: {
        addEventListener: () => {},
        createElement: () => ({click: () => { clicked = true; }}),
        getElementById: (id) => {
            if (!elements.has(id)) elements.set(id, {textContent: '', hidden: true});
            return elements.get(id);
        }
    },
    window: {addEventListener: () => {}}
});
vm.runInContext(source, context);
const run = (code) => vm.runInContext(code, context);
run('resetSearchDebug(); activeSearchAbortController = {};');
run('recordSearchDebug({}, 50, 1, activeSearchAbortController);');
assert.equal(run('searchDebugReport'), null);
context.data = {status: true, debug: {schema_version: 1, total_ms: 10, counts: {returned_ips: 0}}};
clock = 110;
run('recordSearchDebug(data, 50, 0, activeSearchAbortController);');
assert.equal(run('searchDebugReport.first_response_ms'), 100);
assert.equal(run('searchDebugReport.first_results_dom_ms'), undefined);
assert.equal(elements.get('search-debug').hidden, false);
assert.equal(JSON.parse(elements.get('search-debug-report').textContent).page_count, 1);
clock = 210;
context.data.debug.counts = {returned_ips: 1};
run('recordSearchDebug(data, 90, 2, activeSearchAbortController);');
assert.equal(run('searchDebugReport.first_results_dom_ms'), 200);
run('recordSearchDebug(data, 999, 1, {});');
assert.equal(run('searchDebugReport.page_count'), 2); // stale response ignored
run('for (let n = 0; n < 100; n++) recordSearchDebug(data, 10, 1, activeSearchAbortController);');
assert.equal(run('searchDebugReport.pages.length'), 100);
assert.equal(run('searchDebugReport.pages[0].page'), 3);
assert.equal(run('searchDebugReport.page_count'), 102);
assert.equal(run('searchDebugReport.server_ms'), 1020);
assert.equal(run('searchDebugReport.request_ms'), 1140);
run('downloadSearchDebug();');
assert.equal(clicked, true);
assert.equal(downloaded.type, 'application/json');
downloaded.text().then((text) => {
    assert.equal(JSON.parse(text).page_count, 102);
    run('resetSearchDebug();');
    assert.equal(run('searchDebugReport'), null);
    assert.equal(elements.get('search-debug').hidden, true);
    assert.equal(elements.get('search-debug-report').textContent, '');
    console.log('Search debug UI: reports, timings, retention, stale responses, download and reset OK');
});
