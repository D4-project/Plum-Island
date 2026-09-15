// Check the shared asynchronous tag batching used by search and Target Show.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

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
