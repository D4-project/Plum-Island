'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../webapp/app/static/themes/plum/color_mode.js'), 'utf8');

function harness({saved = null, dark = false, blocked = false} = {}) {
    const attributes = {};
    const events = {};
    const system = {matches: dark, addEventListener: (_name, callback) => { system.change = callback; }};
    const viewers = [];
    const values = new Map(saved === null ? [] : [['plum.color-mode', saved]]);
    let ready = false;
    let mutation;
    let domReady;
    const icon = {className: 'fa fa-sun'};
    const button = {attributes: {}, querySelector: () => icon,
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener(name, callback) { this[name] = callback; }};
    const document = {
        documentElement: {setAttribute: (name, value) => { attributes[name] = value; }},
        getElementById: () => ready ? button : null,
        querySelectorAll: () => viewers,
        addEventListener: (_name, callback) => { domReady = callback; }
    };
    const window = {
        matchMedia: () => system,
        localStorage: {
            getItem(key) { if (blocked) throw new Error('Storage denied'); return values.get(key) || null; },
            setItem(key, value) { if (blocked) throw new Error('Storage denied'); values.set(key, value); }
        },
        addEventListener: (name, callback) => { events[name] = callback; }
    };
    vm.runInNewContext(source, {document, window, MutationObserver: class {
        constructor(callback) { mutation = callback; }
        observe() {}
    }});
    const viewer = () => ({theme: null, matches: selector => selector.split(',').map(part => part.trim()).includes('vt-json'),
        setAttribute(_name, value) { this.theme = value; }});
    return {
        attributes, button, icon, system, values, events, viewers, viewer,
        mode: () => attributes['data-plum-color-mode'],
        ready() { ready = true; viewers.push(viewer()); domReady(); },
        add(node) { mutation([{addedNodes: [node]}]); }
    };
}

const follow = harness({dark: true});
assert.equal(follow.mode(), 'dark', 'apply system preference before body renders');
follow.ready();
assert.equal(follow.button.attributes['aria-pressed'], 'true');
assert.equal(follow.icon.className, 'fa fa-moon', 'initial icon reflects the active dark mode');
assert.equal(follow.viewers[0].theme, 'dark');
follow.system.matches = false;
follow.system.change();
assert.equal(follow.mode(), 'light', 'follow system changes without an explicit choice');
assert.equal(follow.icon.className, 'fa fa-sun');
follow.button.click();
assert.equal(follow.mode(), 'dark');
assert.equal(follow.button.title, undefined, 'the icon-only toggle has no text tooltip');
assert.equal(follow.icon.className, 'fa fa-moon', 'clicking switches the sun to a moon');
assert.equal(follow.values.get('plum.color-mode'), 'dark');
follow.system.change();
assert.equal(follow.mode(), 'dark', 'system changes must preserve a manual choice');
const added = follow.viewer();
follow.add(added);
assert.equal(added.theme, 'dark', 'new JSON viewers inherit the current mode');
follow.viewers.push(added);
follow.button.click();
assert.equal(added.theme, 'light', 'existing JSON viewers update on toggle');
assert.equal(follow.button.attributes['aria-pressed'], 'false');
assert.equal(follow.icon.className, 'fa fa-sun', 'clicking again restores the sun');
follow.values.set('plum.color-mode', 'dark');
follow.events.storage({key: 'plum.color-mode'});
assert.equal(follow.mode(), 'dark', 'other tabs synchronize saved choices');
assert.equal(follow.icon.className, 'fa fa-moon', 'other tabs also synchronize the icon');
follow.values.clear();
follow.events.storage({key: null});
assert.equal(follow.mode(), 'light', 'clearing a saved choice restores system preference');

const restored = harness({saved: 'light', dark: true});
assert.equal(restored.mode(), 'light', 'saved preference wins over system preference');
assert.equal(harness({saved: 'invalid', dark: true}).mode(), 'dark');
const privateMode = harness({blocked: true});
privateMode.ready();
privateMode.button.click();
assert.equal(privateMode.mode(), 'dark', 'storage failures do not break the toggle');
privateMode.system.change();
assert.equal(privateMode.mode(), 'dark', 'manual choice survives storage failures on this page');
console.log('Plum color mode: persistence, system preference, accessibility and JSON viewers OK');
