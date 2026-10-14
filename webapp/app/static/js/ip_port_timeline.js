/* Per-port observation histories. No network requests or HTML from scan data. */
(function (root) {
    'use strict';
    const NS = 'http://www.w3.org/2000/svg';
    function timestamp(value) {
        if (value === null || value === undefined || String(value).trim() === '') return null;
        const seconds = Number(value);
        return Number.isFinite(seconds) && Math.abs(seconds * 1000) <= 8640000000000000
            ? seconds : null;
    }
    function interval(first, last) {
        const start = timestamp(first), end = timestamp(last);
        if (start === null && end === null) return null;
        // Invalid reversed bounds are shown as a last-seen point, not invented history.
        return {start: start === null || (end !== null && start > end) ? end : start,
            end: end === null ? start : end};
    }
    function formatDate(value) {
        const seconds = timestamp(value);
        return seconds === null ? 'N/A'
            : new Date(seconds * 1000).toISOString().slice(0, 19).replace('T', ' ');
    }
    function bounds(items) {
        let min = Infinity, max = -Infinity;
        items.forEach(item => {
            if (item.range) { min = Math.min(min, item.range.start); max = Math.max(max, item.range.end); }
            const live = timestamp(item.verifiedAt);
            if (live !== null) { min = Math.min(min, live); max = Math.max(max, live); }
        });
        if (Number.isFinite(min) && min === max) {
            // A lone date gets five approximate months, centered on its point.
            const halfWindow = 75 * 86400;
            return {min: min - halfWindow, max: max + halfWindow};
        }
        return Number.isFinite(min) ? {min, max} : null;
    }
    function layout(items, domain, width) {
        const inset = 14, span = Math.max(0, width - inset * 2);
        const x = value => domain.max === domain.min ? width / 2
            : inset + (value - domain.min) / (domain.max - domain.min) * span;
        return items.filter(item => item.range).slice().sort((a, b) =>
            a.range.start - b.range.start || a.range.end - b.range.end
        ).map(item => {
            const start = x(item.range.start), end = x(item.range.end);
            return {item, start, end};
        });
    }
    function mount(doc, entries, options = {}) {
        const cards = entries || Array.from(doc.querySelectorAll('.ip-port-card')).map(card => ({
            card, host: card.querySelector('.ip-port-timeline'),
            items: Array.from(card.querySelectorAll('.ip-port-tabs > li')).map(tab => ({
                tab, link: tab.querySelector('a'),
                range: interval(tab.getAttribute('data-first-seen'), tab.getAttribute('data-last-seen')),
            })),
        })).filter(entry => entry.host);
        let domain = null;
        const controls = new Map();
        function node(tag, attrs, text) {
            const element = doc.createElementNS(NS, tag);
            Object.entries(attrs || {}).forEach(([key, value]) => element.setAttribute(key, String(value)));
            if (text !== undefined) element.textContent = text;
            return element;
        }
        function sync() {
            controls.forEach((tab, control) => control.setAttribute('aria-pressed', String(tab.classList.contains('active'))));
        }
        function render(entry) {
            const {card, host, items} = entry;
            if (card.style.display === 'none') return;
            const width = host.getBoundingClientRect().width;
            if (!width) return; // Hidden outer tab; ResizeObserver redraws when visible.
            controls.forEach((_tab, control) => { if (host.contains(control)) controls.delete(control); });
            host.replaceChildren();
            const visible = items.filter(item => item.tab.style.display !== 'none');
            const positions = domain ? layout(visible, domain, width) : [];
            const height = options.compact ? 36 : 58;
            if (domain) {
                const svg = node('svg', {width: '100%', height, role: 'group', 'aria-label': 'Observation periods (UTC); not continuous availability'});
                const count = domain.min === domain.max ? 1 : Math.max(2, Math.min(6, Math.floor(width / 140)));
                for (let i = 0; !options.compact && i < count; i += 1) {
                    const fraction = count === 1 ? 0.5 : i / (count - 1);
                    const time = domain.min + (domain.max - domain.min) * fraction;
                    const x = 14 + (width - 28) * fraction;
                    svg.appendChild(node('line', {x1: x, x2: x, y1: 23, y2: height - 8, class: 'ip-timeline-axis'}));
                    const date = new Date(time * 1000).toISOString();
                    const label = domain.max - domain.min < 86400 ? date.slice(11, 19) : date.slice(0, 10);
                    const text = node('text', {x, y: 14, 'text-anchor': count === 1 ? 'middle' : i === 0 ? 'start' : i === count - 1 ? 'end' : 'middle', class: 'ip-timeline-label'}, label);
                    text.appendChild(node('title', {}, date.slice(0, 19).replace('T', ' ')));
                    svg.appendChild(text);
                }
                const startMarks = [];
                const pointMarks = [];
                const tooltip = node('g', {visibility: 'hidden', 'pointer-events': 'none', class: 'ip-timeline-tooltip'});
                tooltip.appendChild(node('rect', {width: 218, height: 24, rx: 3, fill: '#263746'}));
                const tooltipText = node('text', {x: 8, y: 16, fill: '#fff', 'font-size': 11, 'font-family': 'sans-serif'});
                tooltip.appendChild(tooltipText);
                function bindTooltip(element, label, x) {
                    const show = () => {
                        tooltipText.textContent = label;
                        tooltip.setAttribute('transform', `translate(${Math.max(0, Math.min(x - 109, width - 218))}, ${options.compact ? -12 : 1})`);
                        tooltip.setAttribute('visibility', 'visible');
                    };
                    const hide = () => tooltip.setAttribute('visibility', 'hidden');
                    element.addEventListener('pointerenter', show);
                    element.addEventListener('pointerleave', hide);
                    element.addEventListener('focus', show);
                    element.addEventListener('blur', hide);
                }
                positions.forEach(({item, start, end}) => {
                    const y = options.compact ? 18 : 38;
                    const dateLabel = attribute => formatDate(item.tab.getAttribute(attribute));
                    const label = `First seen: ${dateLabel('data-first-seen')} | Last seen: ${dateLabel('data-last-seen')}`;
                    if (start !== end && timestamp(item.tab.getAttribute('data-first-seen')) !== null) {
                        const mark = node('line', {x1: start, x2: start, y1: y - 6, y2: y + 6,
                            class: 'ip-timeline-range', 'pointer-events': 'stroke'});
                        mark.appendChild(node('title', {}, dateLabel('data-first-seen')));
                        startMarks.push(mark);
                        const hit = node('line', {x1: start, x2: start, y1: y - 7, y2: y + 7,
                            stroke: 'transparent', 'stroke-width': 10, 'pointer-events': 'stroke',
                            class: 'ip-timeline-start-hit', tabindex: 0, role: 'button',
                            'aria-label': `First seen: ${dateLabel('data-first-seen')}`});
                        bindTooltip(hit, dateLabel('data-first-seen'), start);
                        hit.addEventListener('click', () => { item.link.click(); sync(); });
                        hit.addEventListener('keydown', event => {
                            if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault(); item.link.click(); sync();
                            }
                        });
                        startMarks.push(hit);
                    }
                    if (start !== end) svg.appendChild(node('line', {x1: start, x2: end, y1: y, y2: y, class: 'ip-timeline-range'}));
                    const point = node('g', {class: 'ip-timeline-point', role: 'button', tabindex: 0,
                        'aria-label': label, 'aria-controls': item.link.getAttribute('aria-controls')});
                    point.appendChild(node('title', {}, dateLabel('data-last-seen')));
                    point.appendChild(node('circle', {cx: end, cy: y, r: 13, fill: 'transparent', class: 'ip-timeline-hit'}));
                    point.appendChild(node('circle', {cx: end, cy: y, r: 5, class: 'ip-timeline-dot'}));
                    bindTooltip(point, dateLabel('data-last-seen'), end);
                    point.addEventListener('click', () => { item.link.click(); sync(); });
                    point.addEventListener('keydown', event => {
                        if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault(); item.link.click(); sync();
                        }
                    });
                    controls.set(point, item.tab);
                    pointMarks.push(point);
                });
                // Live DNS is an overlay, never a replacement for passive history.
                visible.forEach(item => {
                    const verifiedAt = timestamp(item.verifiedAt);
                    if (verifiedAt === null) return;
                    const last = timestamp(item.tab.getAttribute('data-last-seen'));
                    const range = {start: last !== null && last <= verifiedAt ? last : verifiedAt, end: verifiedAt};
                    const position = layout([{range}], domain, width)[0];
                    const y = options.compact ? 18 : 38;
                    if (position.start !== position.end) {
                        svg.appendChild(node('line', {x1: position.start, x2: position.end, y1: y, y2: y,
                            class: 'ip-pdns-live-range'}));
                    }
                    const label = formatDate(verifiedAt);
                    const point = node('g', {class: 'ip-pdns-live-point', tabindex: 0, role: 'button',
                        'aria-label': label, 'aria-controls': item.link.getAttribute('aria-controls')});
                    point.appendChild(node('title', {}, label));
                    point.appendChild(node('circle', {cx: position.end, cy: y, r: 13, fill: 'transparent'}));
                    point.appendChild(node('circle', {cx: position.end, cy: y, r: 6, class: 'ip-pdns-live-dot'}));
                    bindTooltip(point, label, position.end);
                    point.addEventListener('click', () => { item.link.click(); sync(); });
                    point.addEventListener('keydown', event => {
                        if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault(); item.link.click(); sync();
                        }
                    });
                    controls.set(point, item.tab);
                    pointMarks.push(point);
                });
                // Paint all connectors behind both historical and live points.
                pointMarks.forEach(point => svg.appendChild(point));
                // Keep start ticks hoverable above the enlarged point hit areas.
                startMarks.forEach(mark => svg.appendChild(mark));
                svg.appendChild(tooltip);
                host.appendChild(svg);
            }
            visible.filter(item => !item.range).forEach((item, index) => {
                const button = doc.createElement('button');
                button.type = 'button';
                button.className = 'btn btn-default btn-xs ip-timeline-undated';
                button.textContent = `Unknown date ${index + 1}`;
                button.setAttribute('aria-controls', item.link.getAttribute('aria-controls'));
                button.addEventListener('click', () => { item.link.click(); sync(); });
                controls.set(button, item.tab);
                host.appendChild(button);
            });
            card.classList.add('timeline-ready');
        }
        function refresh() {
            // One shared scale across ports, but only for the current hostname.
            domain = bounds(cards.filter(entry => entry.card.style.display !== 'none')
                .flatMap(entry => entry.items.filter(item => item.tab.style.display !== 'none')));
            cards.forEach(render);
            sync();
            if (options.axisHost && options.gridHost && domain) {
                const rect = options.axisHost.getBoundingClientRect();
                if (!rect.width) return;
                const containerRect = options.container.getBoundingClientRect();
                const top = rect.bottom - containerRect.top;
                const gridHeight = Math.max(0, containerRect.height - top);
                Object.assign(options.gridHost.style, {left: `${rect.left - containerRect.left}px`,
                    top: `${top}px`, width: `${rect.width}px`, height: `${gridHeight}px`});
                const axis = node('svg', {width: '100%', height: 24, 'aria-label': 'Passive DNS dates (UTC)'});
                const grid = node('svg', {width: '100%', height: gridHeight, 'aria-hidden': 'true'});
                const count = Math.max(2, Math.min(6, Math.floor(rect.width / 140)));
                for (let i = 0; i < count; i += 1) {
                    const fraction = i / (count - 1);
                    const x = 14 + (rect.width - 28) * fraction;
                    const date = new Date((domain.min + (domain.max - domain.min) * fraction) * 1000).toISOString();
                    const text = node('text', {x, y: 16, 'text-anchor': i === 0 ? 'start' : i === count - 1 ? 'end' : 'middle',
                        class: 'ip-timeline-label'}, domain.max - domain.min < 86400 ? date.slice(11, 19) : date.slice(0, 10));
                    text.appendChild(node('title', {}, date.slice(0, 19).replace('T', ' ')));
                    axis.appendChild(text);
                    grid.appendChild(node('line', {x1: x, x2: x, y1: 0, y2: gridHeight, class: 'ip-timeline-axis'}));
                }
                options.axisHost.replaceChildren(axis);
                options.gridHost.replaceChildren(grid);
            }
        }
        let widthObserver = null;
        if (root.ResizeObserver) {
            // Watch width changes only: rendering may change a timeline's height.
            const widths = new Map();
            widthObserver = new root.ResizeObserver(entries => {
                let changed = false;
                entries.forEach(entry => {
                    const old = widths.get(entry.target);
                    widths.set(entry.target, entry.contentRect.width);
                    if (old !== entry.contentRect.width) changed = true;
                });
                if (changed) refresh();
            });
            cards.forEach(entry => widthObserver.observe(entry.host));
        } else if (root.addEventListener) root.addEventListener('resize', refresh);
        refresh();
        function destroy() {
            if (widthObserver) widthObserver.disconnect();
            else if (root.removeEventListener) root.removeEventListener('resize', refresh);
            controls.clear();
        }
        return {refresh, sync, destroy};
    }
    const api = {timestamp, interval, formatDate, bounds, layout, mount};
    root.PlumPortTimeline = api;
    if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
