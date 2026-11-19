// Check search keyword helpers append only supported query fields.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
    require('./ui_template_paths').templatePath('search_kvrocks.html'), 'utf8'
);
const shared = fs.readFileSync(path.join(__dirname,
    '../webapp/app/static/js/search_autocomplete.js'), 'utf8');
assert.match(source, /{% include 'search_query_helpers.html' %}/);
assert.doesNotMatch(source, /function (getQueryTagContext|appendSearchKeyword|bindQueryTagHelper)\(/);
const helpers = shared.slice(shared.indexOf('const SEARCH_KEYWORDS'));

const input = {
    value: 'net:192.0.2.0/24',
    focusCalls: 0,
    selection: null,
    events: [],
    focus() { this.focusCalls += 1; },
    setSelectionRange(start, end) {
        this.selection = [start, end];
        this.selectionStart = start;
        this.selectionEnd = end;
    },
    dispatchEvent(event) { this.events.push(event.type); }
};
const keywordData = {textContent: process.env.PLUM_SEARCH_KEYWORDS || JSON.stringify([
    'http_title', 'http_server', 'http_headval', 'port', 'tag', 'since', 'x509_subject'
])};
const context = vm.createContext({
    document: {getElementById: id => ({query: input, 'search-keywords': keywordData})[id]},
    Event
});
vm.runInContext(helpers, context);

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
    dataset, listeners: {}, attributes: {}, focusCalls: 0,
    addEventListener(name, callback) { this.listeners[name] = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
    focus() { this.focusCalls += 1; }
});
const keywords = [element({searchKeyword: 'port'})];
const tagLabels = ['proto:ssh', 'type:firewall', 'product:nginx', 'vendor:ovh', 'vuln:cve-2025-1234'];
const tags = tagLabels.map(label => element({searchTagTerm: `tag:${label}`}));
const toggles = [element(), element(), element()];
const helpToggles = [element(), element(), element()];
const helpPanel = {hidden: true, dataset: {}, querySelector: () => helpToggles[2]};
const tables = [
    {hidden: false, querySelector: selector => selector === '[data-search-examples-toggle]' ? helpToggles[0] : toggles[0]},
    {hidden: true, querySelector: selector => selector === '[data-search-examples-toggle]' ? helpToggles[1] : toggles[1]}
];
context.document.getElementById = id => ({query: input, 'search-keyword-table': tables[0], 'search-tag-table': tables[1], 'scan-query-help': helpPanel})[id];
context.document.querySelectorAll = selector => ({
    '[data-search-keyword]': keywords,
    '[data-search-tag-term]': tags,
    '[data-search-helper-toggle]': toggles,
    '[data-search-examples-toggle]': helpToggles
})[selector] || [];
context.bindSearchKeywordHelpers();
input.value = 'port:443';
for (const tag of tags) tag.listeners.click();
assert.equal(input.value, 'port:443 ' + tagLabels.map(label => `tag:${label}`).join(' '));
assert.deepEqual(input.selection, [input.value.length, input.value.length]);
const savedQuery = input.value;
assert.equal(helpPanel.hidden, true);
helpToggles[0].listeners.click();
assert.equal(helpPanel.hidden, false);
assert.ok(tables.every(table => table.hidden), 'examples replace both tables');
assert.equal(helpToggles[2].focusCalls, 1);
assert.ok(helpToggles.every(button => button.attributes['aria-expanded'] === 'true'));
helpToggles[2].listeners.click();
assert.equal(helpPanel.hidden, true);
assert.equal(tables[0].hidden, false);
assert.equal(tables[1].hidden, true);
assert.ok(helpToggles.every(button => button.attributes['aria-expanded'] === 'false'));
toggles[0].listeners.click();
assert.equal(tables[0].hidden, true);
assert.equal(tables[1].hidden, false);
assert.equal(toggles[1].focusCalls, 1);
helpToggles[1].listeners.click();
assert.equal(helpPanel.hidden, false);
assert.ok(tables.every(table => table.hidden));
helpToggles[2].listeners.click();
assert.equal(helpPanel.hidden, true);
assert.equal(tables[0].hidden, true);
assert.equal(tables[1].hidden, false, 'closing examples restores tags');
helpToggles[1].listeners.click();
toggles[2].listeners.click();
assert.equal(helpPanel.hidden, true, 'swap leaves the example view');
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
const catalogue = fs.readFileSync(require('./ui_template_paths').templatePath('search_tag_catalogue.html'), 'utf8');
// Native buttons provide Enter/Space activation without duplicate key handlers.
assert.match(catalogue, /<button type="button" data-search-tag-term=/);
assert.match(source, /<th>Description\s*<button[^>]*data-search-helper-toggle/);

console.log('Search keyword helpers: allowlisted append and neutral controls OK');

assert.match(source, /{% include 'search_query_examples.html' %}/);
assert.match(source, /aria-describedby="scan-query-help"/);
const examplesSource = fs.readFileSync(path.join(__dirname,
    '../webapp/app/templates/search_query_examples.html'), 'utf8');
assert.match(examplesSource, /id="scan-query-help" hidden/);
assert.match(source, /{% include 'search_examples_toggle.html' %}/);
assert.match(catalogue, /{% include 'search_examples_toggle.html' %}/);
const exampleMarkup = [...examplesSource.matchAll(/<button type="button"[^>]*data-query-example="([^"]+)">([\s\S]*?)<\/button>/g)];
const examples = exampleMarkup.map(match => element({queryExample: match[1]}));
assert.deepEqual(examples.map(button => button.dataset.queryExample), [
    'port:443 AND http_server.lk:nginx', 'port:443 OR port:22',
    '(port:443 AND http_server.lk:nginx) OR (port:22)',
    'port:443 AND NOT http_server.lk:nginx',
    'http_server.bg:nginx', 'http_server.lk:nginx', 'http_headval:x-powered-by.lk:php'
]);
assert.match(examplesSource, /starts with <code>nginx<\/code>/);
assert.match(examplesSource, /contains <code>nginx<\/code> anywhere/);
assert.equal((examplesSource.match(/<div>/g) || []).length, 7, 'seven example cards');
assert.equal((examplesSource.match(/<h3>[\s\S]*?<\/h3>\s*<p>[\s\S]*?<\/p>\s*<button/g) || []).length,
    7, 'each card explains its behavior before the example button');
assert.doesNotMatch(examplesSource, /Try an example:/);
for (const match of exampleMarkup) {
    assert.equal(match[2].match(/<code>([\s\S]*?)<\/code>/)[1], match[1],
        'card displays the query inserted by its button');
}
const exampleInput = {
    value: 'existing query', focusCalls: 0, events: [],
    focus() { this.focusCalls += 1; },
    setSelectionRange(start, end) { this.selection = [start, end]; },
    dispatchEvent(event) { this.events.push([event.type, event.bubbles]); }
};
const exampleContext = vm.createContext({
    document: {
        querySelectorAll: () => examples,
        getElementById: id => ({query: exampleInput, 'search-keywords': keywordData})[id]
    }, Event
});
// Load the entire common asset as a browser does; accidental submission fails.
vm.runInContext(shared, exampleContext);
exampleContext.bindSearchQueryExamples();
for (const button of examples) {
    button.listeners.click();
    assert.equal(exampleInput.value, button.dataset.queryExample);
    assert.deepEqual(exampleInput.selection, [exampleInput.value.length, exampleInput.value.length]);
}
assert.equal(exampleInput.focusCalls, 7);
assert.deepEqual(exampleInput.events, Array.from({length: 7}, () => ['input', true]));
console.log('Shared examples: visible syntax, inserted queries, caret and input events OK');

// Exercise the real autocomplete functions with a small observable DOM.
function node(tag = 'div') {
    return {
        tag, children: [], listeners: {}, dataset: {}, style: {display: 'none'},
        classList: {toggle() {}},
        set textContent(value) { this.text = value; this.children = []; },
        get textContent() { return this.text; },
        set innerHTML(_value) { this.children = []; },
        appendChild(child) { this.children.push(child); },
        addEventListener(name, callback) { this.listeners[name] = callback; },
        querySelectorAll() { return this.children; },
        scrollIntoView() {},
        contains(child) { return this.children.includes(child); }
    };
}
const menu = node();
context.document.getElementById = id => ({query: input, 'query-tag-suggest': menu, 'search-keywords': keywordData})[id];
context.document.createElement = node;
Object.assign(context, {
    AbortController, URLSearchParams,
    setTimeout, clearTimeout,
    readJsonResponse: async response => response,
    search() { throw new Error('completion must not submit search'); },
    syncSinceDirectiveState() {}
});
input.listeners = {};
input.addEventListener = (name, callback) => { input.listeners[name] = callback; };
const state = shared.match(/let tagSuggestAbortController[\s\S]*?let tagSuggestRequestId = 0;/);
assert.ok(state);
vm.runInContext(state[0] + '\nconst TAG_SUGGEST_DEBOUNCE_MS = 0;\n' + shared.slice(
    shared.indexOf('function getTagSuggestMenu()'), shared.indexOf('const SEARCH_KEYWORDS')
), context);

function query(value, caret = value.length) {
    input.value = value;
    input.setSelectionRange(caret, caret);
    context.scheduleTagSuggestionFetch();
}
function labels() { return menu.children.map(button => button.children[0].textContent); }
function key(name) {
    let prevented = false;
    context.handleQueryKeydown({key: name, preventDefault() { prevented = true; }});
    assert.equal(prevented, true);
}
function choose() { menu.children[0].listeners.click(); }

async function checkAutocomplete() {
    let requests = 0;
    context.fetch = () => { requests += 1; throw new Error('keywords require no network'); };
    query('po');
    assert.deepEqual(labels(), ['port:']);
    choose();
    assert.equal(input.value, 'port:');
    assert.equal(input.selectionStart, 5);
    assert.equal(menu.style.display, 'none');

    query('port:443 AND (po OR tag:proto:ssh)', 16);
    assert.deepEqual(labels(), ['port:']);
    key('Tab');
    assert.equal(input.value, 'port:443 AND (port: OR tag:proto:ssh)');
    assert.equal(input.selectionStart, 19);

    query('NOT (Po)');
    assert.equal(menu.style.display, 'none'); // caret after closing parenthesis
    query('NOT (Po)', 7);
    key('Enter');
    assert.equal(input.value, 'NOT (port:)');
    assert.equal(input.selectionStart, 10);

    query('http_');
    assert.deepEqual(labels(), JSON.parse(keywordData.textContent)
        .filter(keyword => keyword.startsWith('http_')).map(keyword => `${keyword}:`));
    assert.ok(labels().includes('http_title:'));
    assert.ok(labels().includes('http_headval:'));
    key('ArrowDown');
    key('ArrowUp');
    key('Escape');
    assert.equal(menu.style.display, 'none');
    assert.equal(input.value, 'http_');

    query('x509_');
    assert.ok(labels().includes('x509_subject:'));
    query('since');
    assert.deepEqual(labels(), ['since:']);
    key('Enter');
    assert.equal(input.value, 'since:');

    query('http_server');
    assert.deepEqual(labels(), ['http_server:', 'http_server.bg:', 'http_server.lk:']);
    query('http_server.');
    assert.deepEqual(labels(), ['http_server.bg:', 'http_server.begin:', 'http_server.lk:', 'http_server.like:']);
    assert.equal(menu.children[0].children[1].textContent, 'starts with');
    assert.equal(menu.children[2].children[1].textContent, 'contains');
    query('http_server.b');
    assert.deepEqual(labels(), ['http_server.bg:', 'http_server.begin:']);
    key('Tab');
    assert.equal(input.value, 'http_server.bg:');
    assert.equal(input.selectionStart, input.value.length);
    query('port:443 AND (http_server.l OR port:22)', 27);
    assert.deepEqual(labels(), ['http_server.lk:', 'http_server.like:']);
    key('Enter');
    assert.equal(input.value, 'port:443 AND (http_server.lk: OR port:22)');
    query('http_server.li');
    choose();
    assert.equal(input.value, 'http_server.like:');
    for (const value of ['tag.', 'since.', 'http_headval.', 'unsupported.bg', 'http_server.xx', 'http_server.lk:nginx', 'http_title:"http_server.b']) {
        query(value);
        assert.equal(menu.style.display, 'none', value);
    }

    // A caret inside an unfinished field replaces the whole token only.
    query('http_title OR port:443', 5);
    choose();
    assert.ok(input.value.endsWith(' OR port:443'));
    assert.ok(input.value.slice(0, input.selectionStart).endsWith(':'));
    for (const [value, caret] of [
        ['http_title:"hello po', undefined],
        ["http_title:'hello po", undefined],
        ['http_title:"hello \\" po', undefined],
        ['http_title:"po"', 13],
        ['port:443', 2],
        ['http_headval:server:nginx', undefined],
        ['ip:192.0.2.1', undefined],
        ['"po"', undefined],
        ['po\\rt', undefined],
        ['', undefined],
        ['OR', undefined],
        ['not_a_real_keyword', undefined]
    ]) {
        query(value, caret);
        assert.equal(menu.style.display, 'none', value);
        assert.equal(input.value, value);
    }
    query('http_title:"hello world" AND po');
    choose();
    assert.equal(input.value, 'http_title:"hello world" AND port:');
    query('po');
    input.selectionEnd = 1;
    context.scheduleTagSuggestionFetch();
    assert.equal(menu.style.display, 'none');
    assert.equal(requests, 0);

    // Stale menus must not overwrite edits made before a click.
    query('po');
    input.value = 'new query';
    choose();
    assert.equal(input.value, 'new query');

    const calls = [];
    context.fetch = (url, options) => new Promise((resolve, reject) => calls.push({url, options, resolve, reject}));
    query('ta');
    choose();
    assert.equal(input.value, 'tag:');
    assert.equal(context.getQueryTagContext().suggestType, 'tag');
    context.hideTagSuggestions();
    query('http_headval');
    choose();
    assert.equal(input.value, 'http_headval:');
    assert.equal(context.getQueryTagContext().suggestType, 'header');
    context.hideTagSuggestions();
    query('(tag:proto:s');
    let pending = context.fetchTagSuggestions(context.getQueryTagContext());
    calls[0].resolve({suggestions: [{label: 'proto:ssh', value: 'tag:proto:ssh', kind: 'tag'}]});
    await pending;
    key('Enter');
    assert.equal(input.value, '(tag:proto:ssh ');

    query('http_headval:ser');
    pending = context.fetchTagSuggestions(context.getQueryTagContext());
    assert.ok(calls[1].url.startsWith('/kvsearchview/header_suggest?'));
    calls[1].resolve({suggestions: [{label: 'server', value: 'http_headval:server:', kind: 'header'}]});
    await pending;
    choose();
    assert.equal(input.value, 'http_headval:server:');

    // Responses and failures from cancelled requests cannot hide local keywords.
    for (const fail of [false, true]) {
        query('tag:proto:s');
        pending = context.fetchTagSuggestions(context.getQueryTagContext());
        const stale = calls.at(-1);
        query('po');
        assert.equal(stale.options.signal.aborted, true);
        if (fail) stale.reject(new Error('late failure'));
        else stale.resolve({suggestions: [{label: 'stale', value: 'stale', kind: 'tag'}]});
        await pending;
        assert.deepEqual(labels(), ['port:']);
    }
    query('tag:proto:s');
    pending = context.fetchTagSuggestions(context.getQueryTagContext());
    calls.at(-1).reject(new Error('backend unavailable'));
    await pending;
    assert.equal(menu.style.display, 'none');
    assert.equal(input.value, 'tag:proto:s');
    query('po');
    assert.deepEqual(labels(), ['port:']);
    context.hideTagSuggestions();
    console.log('Keyword autocomplete: prefixes, caret, quotes, keyboard and stale responses OK');
}
checkAutocomplete().catch(error => { console.error(error); process.exitCode = 1; });
