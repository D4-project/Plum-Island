/* Browser queue/controller without network or a real DNS resolver. */
const assert = require('node:assert/strict');
const {mount} = require('../webapp/app/static/js/ip_pdns_resolve.js');
const tick = () => new Promise(resolve => setImmediate(resolve));
function button() {
    return {disabled: true, attrs: {}, events: {},
        setAttribute(key, value) { this.attrs[key] = value; },
        addEventListener(key, value) { this.events[key] = value; },
        removeEventListener(key) { delete this.events[key]; }};
}
function response(hostname, status = 'matched', ok = true, code = 200) {
    return {ok, status: code, json: async () => ({hostname, status, checked_at: 100})};
}
async function main() {
    const control = button(), progress = {}, results = [];
    const timeline = {targets: Array.from({length: 6}, (_, i) => ({hostname: `host${i}.org`, token: String(i)})),
        setResult: (name, result) => results.push([name, result])};
    let active = 0, maximum = 0;
    const pending = [];
    const fetcher = (_url, options) => {
        assert.equal(options.method, 'POST');
        assert.equal(options.headers['X-CSRFToken'], 'csrf');
        assert.deepEqual(Object.keys(JSON.parse(options.body)), ['token']);
        active += 1; maximum = Math.max(maximum, active);
        return new Promise(resolve => pending.push(payload => { active -= 1; resolve(payload); }));
    };
    const controller = mount(control, progress, timeline, '/resolve', 'csrf', fetcher);
    assert.equal(pending.length, 0); // No query until clicked.
    const run = controller.run();
    await controller.run(); // Double click cannot start another batch.
    assert.equal(pending.length, 4);
    assert.equal(control.disabled, true);
    pending.shift()(response('host0.org'));
    pending.shift()(response('host1.org', 'mismatch'));
    await tick();
    assert.equal(pending.length, 4);
    pending.shift()(response('host2.org', 'nxdomain'));
    pending.shift()(response('host3.org', 'busy', false, 429));
    pending.shift()({ok: false, status: 403, json: async () => { throw new Error('HTML response'); }});
    pending.shift()(response('wrong-host.org'));
    await run;
    assert.equal(maximum, 4);
    assert.equal(progress.textContent, 'Resolved 6/6');
    assert.equal(control.disabled, false);
    assert.deepEqual(results.filter(([, result]) => result.status !== 'pending').map(([, result]) => result.status),
        ['matched', 'mismatch', 'nxdomain', 'busy', 'error', 'error']);
    // Cancelling then restarting must ignore old successful replies, even if fetch ignores abort.
    results.length = 0;
    const oldRun = controller.run();
    const oldRequests = pending.splice(0);
    controller.cancel();
    const newRun = controller.run();
    oldRequests.forEach(done => done(response('host0.org')));
    await oldRun;
    assert.equal(results.every(([, result]) => ['pending', 'cancelled'].includes(result.status)), true);
    assert.equal(control.disabled, true); // Old finally must not unlock the new batch.
    controller.cancel();
    pending.splice(0).forEach(done => done(response('host0.org')));
    await newRun;
    assert.equal(results.every(([, result]) => ['pending', 'cancelled'].includes(result.status)), true);
    controller.destroy();
    assert.equal(control.events.click, undefined);
    const empty = button();
    mount(empty, {}, {targets: [], setResult() { throw new Error('No records'); }}, '', '', fetcher);
    assert.equal(empty.disabled, true);
    console.log('Active DNS: explicit trigger, bounded queue, errors, duplicate clicks and stale replies OK');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
