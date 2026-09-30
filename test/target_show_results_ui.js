// Check the shared asynchronous tag batching used by search and Target Show.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Target pages must ignore global tab memory, including BFCache restores.
const template = fs.readFileSync(
    path.join(__dirname, '../webapp/app/templates/show_targetsview.html'), 'utf8'
);
assert.doesNotMatch(template, /<script[^>]+src=[^>]*ab_keep_tab/);
const tabScript = template.match(/<script id="target-default-tab"[^>]*>([\s\S]*?)<\/script>/)[1];
for (const savedTab of ['#TargetWhois', '#TargetResults', '#JobsView']) {
    let activeTab = savedTab;
    const ready = [];
    const events = {};
    const detail = {};
    const location = {hash: savedTab, pathname: '/targetsview/show/541', search: '?next=1'};
    const history = {state: {keep: true}, replaceState(state, _title, url) {
        assert.equal(state, this.state);
        assert.equal(url, '/targetsview/show/541?next=1');
        location.hash = '';
    }};
    vm.runInNewContext(tabScript, {
        document: {title: 'Target', querySelector: () => detail},
        window: {location, history, addEventListener: (name, callback) => {events[name] = callback;}},
        localStorage: {getItem: () => savedTab, setItem: () => assert.fail('No global storage writes')},
        $: value => {
            if (typeof value === 'function') return ready.push(value);
            assert.equal(value, detail);
            return {tab: action => {assert.equal(action, 'show'); activeTab = '#Home';}};
        },
        fetch: () => assert.fail('No automatic results or WHOIS fetch')
    });
    ready.forEach(callback => callback());
    assert.equal(activeTab, '#Home');
    assert.equal(location.hash, '');
    activeTab = '#TargetResults'; // Manual selection remains possible after load.
    events.pageshow({persisted: false});
    assert.equal(activeTab, '#TargetResults');
    events.pageshow({persisted: true});
    assert.equal(activeTab, '#Home');
}

const source = fs.readFileSync(
    path.join(__dirname, '../webapp/app/static/js/ip_tag_enrichment.js'), 'utf8'
);
const requests = [];
const received = [];
const context = vm.createContext({
    window: {},
    AbortController,
    setTimeout,
    clearTimeout,
    console,
    fetch: async (_url, options) => {
        requests.push(JSON.parse(options.body));
        return {json: async () => ({
            tags_by_ip: {
                '203.0.113.10': ['tag:proto:https', 'vendor:Example', 'vendor:example'],
                '203.0.113.11': []
            }
        })};
    }
});
vm.runInContext(source, context);
const enricher = context.window.createIpTagEnricher({
    readJsonResponse: async (response) => response.json(),
    renderTags: (ip, tags) => received.push([ip, [...tags]])
});

enricher.queue(
    {'203.0.113.10': ['uid-1'], '203.0.113.11': ['uid-2']},
    {from_ts: 100, to_ts: 200}
);
setTimeout(() => {
    assert.deepEqual(requests, [{
        ips: ['203.0.113.10', '203.0.113.11'], from_ts: 100, to_ts: 200
    }]);
    assert.deepEqual(received, [
        ['203.0.113.10', ['proto:https', 'vendor:example']],
        ['203.0.113.11', []]
    ]);
    enricher.queue({'203.0.113.10': ['uid-1']}, {from_ts: 100, to_ts: 200});
    setTimeout(() => {
        assert.equal(requests.length, 1);
        console.log('Shared IP tag enrichment: batch, scope and deduplication OK');
    }, 10);
}, 10);
