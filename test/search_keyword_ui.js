// Check search keyword helpers append only supported query fields.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
    path.join(__dirname, '../webapp/app/templates/search_kvrocks.html'), 'utf8'
);
const helpers = source.match(
    /const SEARCH_KEYWORDS[\s\S]*?\n}\n\nfunction buildExportPayload/
);
assert.ok(helpers, 'search keyword helpers must be present');

const input = {
    value: 'net:192.0.2.0/24',
    focusCalls: 0,
    selection: null,
    events: [],
    focus() { this.focusCalls += 1; },
    setSelectionRange(start, end) { this.selection = [start, end]; },
    dispatchEvent(event) { this.events.push(event.type); }
};
const context = vm.createContext({
    document: {getElementById: (id) => (id === 'query' ? input : null)},
    Event
});
vm.runInContext(helpers[0].replace('\n\nfunction buildExportPayload', ''), context);

context.appendSearchKeyword('http_title');
assert.equal(input.value, 'net:192.0.2.0/24 http_title:');
assert.deepEqual(input.selection, [input.value.length, input.value.length]);
assert.deepEqual(input.events, ['input']);

context.appendSearchKeyword('unsupported');
assert.equal(input.value, 'net:192.0.2.0/24 http_title:');

assert.match(
    source,
    /<span class="search-keyword" data-search-keyword="http_title" role="button" tabindex="0">http_title<\/span>/
);
assert.doesNotMatch(source, /<a[^>]*data-search-keyword/);

console.log('Search keyword helpers: allowlisted append and neutral controls OK');
