// Exercise the real search template's export controls without network or a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const template = fs.readFileSync(path.join(__dirname, '../webapp/app/templates/search_kvrocks.html'), 'utf8');
const source = template.split('<script>')[1].split('</script>')[0];
const container = {
    children: [], dataset: {csrf: 'test-csrf'},
    set innerHTML(value) { this.children = []; },
    appendChild(child) { this.children.push(child); }
};
const element = () => ({
    attrs: {}, listeners: {},
    setAttribute(key, value) { this.attrs[key] = value; },
    addEventListener(key, callback) { this.listeners[key] = callback; }
});
let selected;
const context = vm.createContext({
    console,
    window: {addEventListener() {}},
    document: {addEventListener() {}, createElement: element,
        getElementById: id => id === 'download-buttons-container' ? container : null}
});
const tagScript = fs.readFileSync(path.join(__dirname, '../webapp/app/static/js/ip_tag_enrichment.js'), 'utf8');
vm.runInContext(tagScript, context);
vm.runInContext(source, context);
context.startExport = config => { selected = config; };
context.setDownloadButtonState(true);
assert.deepEqual(container.children.map(child => child.id), ['download-ips-btn', 'download-full-export-btn', 'download-resolved-btn']);
const button = container.children[2];
assert.equal(button.type, 'button');
assert.equal(button.attrs['aria-label'], 'Download resolved (CSV)');
assert.match(button.innerHTML, /fa-network-wired/);
button.listeners.click();
assert.equal(selected.counterUnit, 'IPs');
assert.equal(selected.startUrl, '/kvsearchview/export_resolved_start');
assert.equal(selected.downloadUrl, '/kvsearchview/export_resolved_download');
assert.match(template, /'X-CSRFToken': document\.getElementById\('download-buttons-container'\)\.dataset\.csrf/);
context.setDownloadButtonState(false);
assert.equal(container.children.length, 0);
