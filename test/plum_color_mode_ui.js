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
    const button = {attributes: {}, setAttribute(name, value) { this.attributes[name] = value; },
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
    const viewer = () => ({theme: null, matches: selector => selector === 'vt-json',
        setAttribute(_name, value) { this.theme = value; }});
    return {
        attributes, button, system, values, events, viewers, viewer,
        mode: () => attributes['data-plum-color-mode'],
        ready() { ready = true; viewers.push(viewer()); domReady(); },
        add(node) { mutation([{addedNodes: [node]}]); }
    };
}

const follow = harness({dark: true});
assert.equal(follow.mode(), 'dark', 'apply system preference before body renders');
follow.ready();
assert.equal(follow.button.attributes['aria-pressed'], 'true');
assert.equal(follow.viewers[0].theme, 'dark');
follow.system.matches = false;
follow.system.change();
assert.equal(follow.mode(), 'light', 'follow system changes without an explicit choice');
follow.button.click();
assert.equal(follow.mode(), 'dark');
assert.equal(follow.button.title, 'Use light mode');
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
follow.values.set('plum.color-mode', 'dark');
follow.events.storage({key: 'plum.color-mode'});
assert.equal(follow.mode(), 'dark', 'other tabs synchronize saved choices');
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
