/* Actual timeline module with a small DOM double; no backend requests. */
const assert = require('node:assert/strict');
const timeline = require('../webapp/app/static/js/ip_port_timeline.js');
assert.equal(timeline.timestamp(''), null);
assert.equal(timeline.timestamp('NaN'), null);
assert.equal(timeline.timestamp('1e20'), null);
assert.equal(timeline.timestamp('0'), 0);
assert.deepEqual(timeline.interval('', 20), {start: 20, end: 20});
assert.deepEqual(timeline.interval(20, ''), {start: 20, end: 20});
assert.deepEqual(timeline.interval(30, 20), {start: 20, end: 20});
assert.equal(timeline.interval('', ''), null);
const periods = [
    {range: timeline.interval(10, 30)},
    {range: timeline.interval(20, 30)},
    {range: timeline.interval(70, 90)},
];
const domain = timeline.bounds(periods);
assert.deepEqual(domain, {min: 10, max: 90});
const positions = timeline.layout(periods, domain, 828);
assert.equal(positions[0].start, 14);
assert.equal(positions[2].end, 814);
assert.equal(timeline.layout([{range: {start: 10, end: 10}}], {min: 10, max: 10}, 300)[0].end, 150);
assert.equal(timeline.bounds([{range: null}]), null);
const singleDomain = timeline.bounds([{range: {start: 10000000, end: 10000000}}]);
assert.equal(singleDomain.max - singleDomain.min, 150 * 86400);
assert.equal((singleDomain.min + singleDomain.max) / 2, 10000000);
assert.equal(timeline.layout([{range: {start: 10000000, end: 10000000}}], singleDomain, 828)[0].end, 414);

class Element {
    constructor(tag = 'div') {
        this.tag = tag; this.attrs = {}; this.children = []; this.events = {}; this.style = {};
        const classes = new Set();
        this.classList = {add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x),
            toggle: (x, enabled) => enabled ? classes.add(x) : classes.delete(x)};
    }
    setAttribute(key, value) { this.attrs[key] = String(value); }
    getAttribute(key) { return this.attrs[key] ?? null; }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    addEventListener(name, callback) { this.events[name] = callback; }
    click() { if (this.events.click) this.events.click(); }
    contains(child) { return this.children.includes(child) || this.children.some(x => x.contains(child)); }
    getBoundingClientRect() { return {width: 828, height: 200, left: 0, top: 0, bottom: 24}; }
}
const makeCard = (ranges) => {
    const card = new Element(), host = new Element();
    const tabs = ranges.map(([first, last], index) => {
        const tab = new Element('li'), link = new Element('a');
        tab.setAttribute('data-first-seen', first); tab.setAttribute('data-last-seen', last);
        tab.setAttribute('data-user-hostnames', JSON.stringify(index === 1 ? ['test.example.org'] : []));
        link.setAttribute('aria-controls', `pane-${index}`);
        tab.querySelector = () => link;
        link.click = () => { tabs.forEach(x => x.classList.remove('active')); tab.classList.add('active'); };
        return tab;
    });
    tabs[tabs.length - 1].classList.add('active');
    card.querySelector = () => host;
    card.querySelectorAll = () => tabs;
    return {card, host, tabs};
};
const first = makeCard([[10, 30], [20, 30], [70, 90]]);
const second = makeCard([[50, 50], ['', '']]);
const doc = {
    querySelectorAll: () => [first.card, second.card],
    createElementNS: (_ns, tag) => new Element(tag),
    createElement: tag => new Element(tag),
};
const controller = timeline.mount(doc);
const points = entry => entry.host.children[0].children.filter(x => x.getAttribute('class') === 'ip-timeline-point');
assert.equal(points(first).length, 3);
assert.equal(first.host.children[0].getAttribute('height'), '58');
assert.deepEqual(points(first).map(point => point.children[1].getAttribute('cy')), ['38', '38', '38']);
const startMarks = first.host.children[0].children.filter(element =>
    element.tag === 'line' && element.getAttribute('y1') === '32' && element.getAttribute('y2') === '44');
assert.equal(startMarks.length, 3);
assert.equal(startMarks[0].getAttribute('x1'), '14');
assert.equal(startMarks[0].getAttribute('x2'), '14');
assert.equal(startMarks[0].getAttribute('y2'), '44');
assert.equal(startMarks[0].children[0].textContent, '1970-01-01 00:00:10');
assert.equal(startMarks[0].getAttribute('pointer-events'), 'stroke');
assert.equal(second.host.children[0].children.some(x => x.getAttribute('class') === 'ip-timeline-start-hit'), false);
const startHit = first.host.children[0].children.find(x => x.getAttribute('class') === 'ip-timeline-start-hit');
const tooltip = first.host.children[0].children.find(x => x.getAttribute('class') === 'ip-timeline-tooltip');
startHit.events.pointerenter();
assert.equal(tooltip.getAttribute('visibility'), 'visible');
assert.equal(tooltip.children[1].textContent, '1970-01-01 00:00:10');
startHit.events.pointerleave();
assert.equal(tooltip.getAttribute('visibility'), 'hidden');
startHit.events.focus();
assert.equal(tooltip.getAttribute('visibility'), 'visible');
startHit.events.blur();
assert.equal(tooltip.getAttribute('visibility'), 'hidden');
assert.equal(first.card.classList.contains('timeline-ready'), true);
assert.equal(points(first)[2].getAttribute('aria-pressed'), 'true');
points(first)[0].events.click();
assert.equal(points(first)[0].getAttribute('aria-pressed'), 'true');
assert.equal(points(first)[2].getAttribute('aria-pressed'), 'false');
let prevented = false;
points(first)[1].events.keydown({key: ' ', preventDefault: () => { prevented = true; }});
assert.equal(prevented, true);
assert.equal(points(first)[1].getAttribute('aria-pressed'), 'true');
assert.equal(points(first)[1].getAttribute('aria-controls'), 'pane-1');
assert.equal(points(first)[1].getAttribute('aria-label'), 'First seen: 1970-01-01 00:00:20 | Last seen: 1970-01-01 00:00:30');
assert.equal(points(first)[1].children[0].textContent, '1970-01-01 00:00:30');
assert.equal(second.host.children[1].textContent, 'Unknown date 1');
second.host.children[1].events.click();
assert.equal(second.host.children[1].getAttribute('aria-pressed'), 'true');
const endpoint = points(first)[2].children[1].getAttribute('cx');
first.tabs[0].style.display = 'none'; first.tabs[1].style.display = 'none';
controller.refresh();
assert.equal(points(first).length, 1);
assert.equal(points(first)[0].children[1].getAttribute('cx'), endpoint); // latest visible date remains at right
assert.equal(points(second)[0].children[1].getAttribute('cx'), '14'); // earliest visible date moves to left
assert.equal(points(second)[0].children.filter(x => x.tag === 'circle').length, 2); // hit area + dot
second.card.style.display = 'none';
controller.refresh();
assert.equal(first.host.children[0].children.find(x => x.getAttribute('class') === 'ip-timeline-range').getAttribute('x1'), '14');
first.tabs[0].style.display = ''; first.tabs[1].style.display = ''; second.card.style.display = '';
controller.refresh();
assert.equal(points(second)[0].children[1].getAttribute('cx'), '414'); // original bounds restored
first.tabs.forEach(tab => { tab.style.display = 'none'; });
second.tabs[0].style.display = 'none';
controller.refresh();
assert.equal(second.host.children[0].textContent, 'Unknown date 1'); // no fabricated axis for undated-only filter
console.log('Port timelines: hostname-scoped shared scale, overlaps, missing dates, click/keyboard and selection OK');

// Run the actual hostname filter to check per-port counts, not just SVG items.
const fs = require('node:fs');
const vm = require('node:vm');
const template = fs.readFileSync(require('node:path').join(__dirname, '../webapp/app/templates/ip_detail.html'), 'utf8');
const filterSource = ['getObservationHostnames', 'observationMatchesFilter', 'updatePortFilter'].map(name => {
    const start = template.indexOf(`    function ${name}(`);
    const end = template.indexOf('\n    }', start);
    return template.slice(start, end + '\n    }'.length);
}).join('\n');
const filtered = makeCard([[10, 30], [20, 30], [70, 90]]);
const panes = filtered.tabs.map(() => new Element());
const count = new Element();
filtered.card.querySelector = () => count;
filtered.card.querySelectorAll = selector => selector.includes('tabs > li') ? filtered.tabs : panes;
const select = {value: 'test.example.org'}, empty = new Element();
const context = vm.createContext({document: {
    getElementById: id => id === 'scan-hostname-filter' ? select : empty,
    querySelectorAll: () => [filtered.card],
}, portTimelines: null, updatePortSiteLink: () => {}});
vm.runInContext(filterSource, context);
vm.runInContext('updatePortFilter()', context);
assert.equal(count.textContent, '1 observation');
assert.equal(panes[1].classList.contains('active'), true);
select.value = '__ip_only__';
vm.runInContext('updatePortFilter()', context);
assert.equal(count.textContent, '2 observations');
assert.equal(panes[2].classList.contains('active'), true);
select.value = 'missing.example.org';
vm.runInContext('updatePortFilter()', context);
assert.equal(count.textContent, '0 observations');
assert.equal(filtered.card.style.display, 'none');
console.log('Port counts: hostname-only, IP-only and empty selection OK');

const pdns = require('../webapp/app/static/js/ip_pdns_timeline.js');
const container = new Element();
pdns.mount(doc, container, [
    {rdata: 'one.example.org', rrtype: 'A', time_first: 10, time_last: 30, count: 7},
    {rdata: 'two.example.org', rrtype: 'AAAA', time_first: 50, time_last: 90},
    {rdata: '<img src=x onerror=alert(1)>', rrtype: 'TXT', time_first: '', time_last: ''},
    null,
]);
const pdnsRows = target => target.children.filter(x => x.className === 'ip-pdns-row ip-pdns-timeline-row');
assert.equal(pdnsRows(container).length, 3);
const pdnsRow = pdnsRows(container)[0], pdnsLatest = pdnsRows(container)[1];
assert.equal(pdnsRow.children[0].textContent, 'one.example.org (A)');
assert.equal(pdnsRows(container)[2].children[0].textContent, '<img src=x onerror=alert(1)> (TXT)');
assert.equal(pdnsRows(container)[2].children[0].children.length, 0); // text only, never HTML
assert.equal(pdnsLatest.classList.contains('active'), true);
const pdnsPoints = row => row.children[1].children[0].children.filter(x => x.getAttribute('class') === 'ip-timeline-point');
assert.equal(pdnsPoints(pdnsLatest)[0].children[1].getAttribute('cx'), '814');
assert.equal(pdnsRow.children[1].children[0].children.find(x => x.getAttribute('class') === 'ip-timeline-range').getAttribute('x1'), '14');
pdnsPoints(pdnsRow)[0].events.click();
assert.equal(pdnsRow.classList.contains('active'), true);
assert.equal(pdnsLatest.classList.contains('active'), false);
assert.equal(pdnsRows(container)[2].children[1].children[1].textContent, 'Unknown date 1');
assert.equal(pdnsRow.children[1].children[0].getAttribute('height'), '36');
assert.equal(pdnsRow.children[1].children[0].children.some(x => x.getAttribute('class') === 'ip-timeline-label'), false);
assert.equal(container.children[0].children[1].children[0].children.length, 5); // dates only once
assert.equal(container.children[1].children[0].children.length, 5); // continuous grid
const singleton = new Element();
pdns.mount(doc, singleton, [{rdata: 'single.example.org', rrtype: 'A', time_first: 50, time_last: 50}]);
assert.equal(pdnsPoints(pdnsRows(singleton)[0])[0].children[1].getAttribute('cx'), '414');
assert.equal(pdnsRows(singleton)[0].children[1].children[0].children.some(x => x.getAttribute('class') === 'ip-timeline-start-hit'), false);
console.log('Passive DNS: Rdata/type, common independent scale, selection, escaping and singleton OK');
