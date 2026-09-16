// Exercise the actual template helpers, isolating external enrichment requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const template = fs.readFileSync(path.join(__dirname, '../webapp/app/templates/ip_detail.html'), 'utf8');
const source = template.split('<script>')[1].split('</script>')[0];
new vm.Script(source.replace('{{ ip | tojson }}', '"8.8.8.8"'));
const functions = ['formatUrlHost', 'buildPortSiteUrl', 'updatePortSiteLink', 'openPortSite'].map((name) => {
    const start = source.indexOf(`    function ${name}(`);
    assert.ok(start >= 0);
    const end = source.indexOf('\n    }', start);
    return source.slice(start, end + '\n    }'.length);
}).join('\n');
const selector = {value: '__ip_only__'};
const opened = [];
let scheme = 'https';
const pane = {getAttribute: () => scheme};
const button = {
    port: '8443', style: {},
    getAttribute: () => button.port,
    setAttribute: (name, value) => { button[name] = value; },
    closest: () => card
};
const card = {querySelector: (query) => query === '.ip-port-link' ? button : pane};
const context = vm.createContext({
    ip: '8.8.8.8', button, card,
    document: {getElementById: () => selector},
    window: {open: (...args) => opened.push(args)}
});
vm.runInContext(functions, context);
const run = (code) => vm.runInContext(code, context);
assert.equal(run("buildPortSiteUrl('http', '80')"), 'http://8.8.8.8');
assert.equal(run("buildPortSiteUrl('https', '443')"), 'https://8.8.8.8');
assert.equal(run("buildPortSiteUrl('http', '8080')"), 'http://8.8.8.8:8080');
assert.equal(run("buildPortSiteUrl('https', '8443')"), 'https://8.8.8.8:8443');
selector.value = 'router.example.org';
assert.equal(run("buildPortSiteUrl('https', '8443')"), 'https://router.example.org:8443');
selector.value = '__ip_only__';
context.ip = '2001:db8::1';
assert.equal(run("buildPortSiteUrl('https', '8443')"), 'https://[2001:db8::1]:8443');
context.ip = '8.8.8.8';
for (const port of ['0', '65536', 'invalid', "443');alert(1)//"]) {
    assert.equal(run(`buildPortSiteUrl('https', ${JSON.stringify(port)})`), null);
}
assert.equal(run("buildPortSiteUrl('javascript', '443')"), null);
run('updatePortSiteLink(card); openPortSite(button);');
assert.equal(button.style.display, '');
assert.equal(button['aria-label'], 'Open https service');
assert.deepEqual(opened.pop(), ['https://8.8.8.8:8443', '_blank', 'noopener,noreferrer']);
scheme = 'http'; // Another history tab or requested hostname selects plain HTTP.
run('updatePortSiteLink(card); openPortSite(button);');
assert.equal(button.title, 'Open http service');
assert.equal(opened.pop()[0], 'http://8.8.8.8:8443');
scheme = ''; // Untagged observation must hide and disable the link.
run('updatePortSiteLink(card); openPortSite(button);');
assert.equal(button.style.display, 'none');
assert.equal(opened.length, 0);
console.log('IP detail links: schemes, ports, hostname, IPv6 and active observations OK');
