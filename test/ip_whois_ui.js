// Exercise the WHOIS tab handler from the actual IP detail template.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(require('./ui_template_paths').templatePath('ip_detail.html'), 'utf8');
const script = template.match(/<script nonce="\{\{ baselib\.get_nonce\(\) \}\}">([\s\S]*?)<\/script>/);
assert.ok(script, 'WHOIS tab script exists');
const source = script[1].replace(
    "{{ url_for('IPDetailView.whois_lookup', ip=ip) | tojson }}",
    JSON.stringify('/ip/whois?ip=185.194.93.47')
);

async function runCase(response) {
    const elements = {};
    for (const id of ['ip-whois-loading', 'ip-whois-error', 'ip-whois-result']) {
        elements[id] = {style: {}, textContent: ''};
    }
    let copied;
    let onShown;
    const copy = {hidden: true, addEventListener: (_event, fn) => { copy.click = fn; }};
    elements['ip-whois-copy'] = copy;
    let parsed = false;
    const context = vm.createContext({
        window: {copyIpToClipboard: value => { copied = value; }},
        document: {
            querySelector: () => ({}),
            getElementById: (id) => elements[id]
        },
        $: () => ({on: (_event, callback) => { onShown = callback; }}),
        fetch: async () => ({
            ok: response.ok,
            status: response.status,
            headers: {get: () => response.contentType},
            json: async () => {
                parsed = true;
                if (response.jsonError) throw new SyntaxError('Unexpected token <');
                return response.body;
            }
        }),
        Error
    });
    vm.runInContext(source, context);
    assert.equal(typeof onShown, 'function');
    await onShown();
    if (!copy.hidden) copy.click();
    return {elements, parsed, copied};
}

(async () => {
    const record = 'netname: WHOIS record\ngeoloc: 49.6 6.1';
    const success = await runCase({ok: true, status: 200, contentType: 'application/json', body: {query: '185.194.93.47', result: record}});
    assert.equal(success.elements['ip-whois-result'].textContent, record);
    assert.equal(success.copied, record);

    const denied = await runCase({ok: false, status: 403, contentType: 'text/html', jsonError: true});
    assert.match(denied.elements['ip-whois-error'].textContent, /access denied/i);
    assert.equal(denied.parsed, false);
    assert.equal(denied.elements['ip-whois-copy'].hidden, true);

    const login = await runCase({ok: true, status: 200, contentType: 'text/html', jsonError: true});
    assert.match(login.elements['ip-whois-error'].textContent, /unexpected response/i);
    assert.equal(login.parsed, false);

    const invalid = await runCase({ok: false, status: 400, contentType: 'application/json', body: {error: 'Invalid IP'}});
    assert.equal(invalid.elements['ip-whois-error'].textContent, 'Invalid IP');
    assert.equal(invalid.parsed, true);
})().catch((error) => { console.error(error); process.exitCode = 1; });

// Also verify shared freshness labels and the asynchronous target panel.
require('./lookup_cache_ui.js');
