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

const element = (dataset = {}) => ({
    dataset, listeners: {}, focusCalls: 0,
    addEventListener(name, callback) { this.listeners[name] = callback; },
    focus() { this.focusCalls += 1; }
});
const keywords = [element({searchKeyword: 'port'})];
const tagLabels = ['proto:ssh', 'type:firewall', 'product:nginx', 'vendor:ovh', 'vuln:cve-2025-1234'];
const tags = tagLabels.map(label => element({searchTagTerm: `tag:${label}`}));
const toggles = [element(), element()];
const tables = [
    {hidden: false, querySelector: () => toggles[0]},
    {hidden: true, querySelector: () => toggles[1]}
];
context.document.getElementById = id => ({query: input, 'search-keyword-table': tables[0], 'search-tag-table': tables[1]})[id];
context.document.querySelectorAll = selector => ({
    '[data-search-keyword]': keywords,
    '[data-search-tag-term]': tags,
    '[data-search-helper-toggle]': toggles
})[selector];
context.bindSearchKeywordHelpers();
input.value = 'port:443';
for (const tag of tags) tag.listeners.click();
assert.equal(input.value, 'port:443 ' + tagLabels.map(label => `tag:${label}`).join(' '));
assert.deepEqual(input.selection, [input.value.length, input.value.length]);
const savedQuery = input.value;
toggles[0].listeners.click();
assert.equal(tables[0].hidden, true);
assert.equal(tables[1].hidden, false);
assert.equal(toggles[1].focusCalls, 1);
toggles[1].listeners.click();
assert.equal(tables[0].hidden, false);
assert.equal(tables[1].hidden, true);
assert.equal(input.value, savedQuery);
input.value = '';
tags[0].listeners.click();
assert.equal(input.value, 'tag:proto:ssh');
input.value = 'port:443 ';
tags[1].listeners.click();
assert.equal(input.value, 'port:443 tag:type:firewall');
let prevented = false;
keywords[0].listeners.keydown({key: 'Enter', preventDefault() { prevented = true; }});
assert.equal(prevented, true);
assert.ok(input.value.endsWith(' port:'));
const catalogue = fs.readFileSync(path.join(__dirname, '../webapp/app/templates/search_tag_catalogue.html'), 'utf8');
// Native buttons provide Enter/Space activation without duplicate key handlers.
assert.match(catalogue, /<button type="button" data-search-tag-term=/);
assert.match(source, /<th>Description\s*<button[^>]*data-search-helper-toggle/);

console.log('Search keyword helpers: allowlisted append and neutral controls OK');
