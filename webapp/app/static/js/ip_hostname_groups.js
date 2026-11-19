/* Page-lifetime hostname cache. Late replies may be cached, never displayed. */
(function (root) {
    'use strict';

    function createCache(initialKey, initialValue, load, display, state) {
        const cache = new Map([[initialKey, initialValue]]);
        const pending = new Map();
        let revision = 0;
        async function select(key) {
            const current = ++revision;
            if (cache.has(key)) {
                display(cache.get(key));
                state('ready');
                return;
            }
            state('loading');
            try {
                if (!pending.has(key)) {
                    const task = Promise.resolve().then(() => load(key)).then(value => {
                        cache.set(key, value);
                        return value;
                    }).finally(() => pending.delete(key));
                    pending.set(key, task);
                }
                const value = await pending.get(key);
                if (current !== revision) return;
                display(value);
                state('ready');
            } catch (_error) {
                if (current === revision) state('error');
            }
        }
        return {select};
    }

    function mount(options) {
        const {select, container, status, beforeSwap, afterSwap} = options;
        const doc = container.ownerDocument;
        const keyFor = value => value === '__ip_only__' ? '' : value;
        const initial = {
            group: doc.getElementById('ip-scan-group'),
            summary: doc.getElementById('ip-scan-summary')
        };
        let active = initial;

        async function load(key) {
            const url = new URL(root.location.href);
            url.searchParams.set('fragment', '1');
            if (key) url.searchParams.set('hostname', key);
            else url.searchParams.delete('hostname');
            url.hash = '';
            const controller = new AbortController();
            const timeout = root.setTimeout(() => controller.abort(), 60000);
            try {
                const response = await root.fetch(url, {
                    credentials: 'same-origin', cache: 'no-store',
                    headers: {'Accept': 'application/json'}, signal: controller.signal
                });
                if (!response.ok || response.redirected) throw new Error('Unavailable');
                const data = await response.json();
                if (data.hostname !== key || typeof data.html !== 'string') throw new Error('Invalid group');
                // Static, auto-escaped server template from the same protected route.
                // Parsing an inert document never executes its scripts.
                const parsed = new root.DOMParser().parseFromString(data.html, 'text/html');
                const group = parsed.getElementById('ip-scan-group');
                const summary = parsed.getElementById('ip-scan-summary');
                if (!group || !summary) throw new Error('Invalid fragment');
                return {group: doc.importNode(group, true), summary: doc.importNode(summary, true)};
            } finally {
                root.clearTimeout(timeout);
            }
        }

        function display(value) {
            if (value === active) return;
            beforeSwap();
            active.summary.replaceWith(value.summary);
            container.replaceChildren(value.group);
            active = value;
            // Unhide before measuring timeline widths.
            container.hidden = false;
            active.summary.hidden = false;
            afterSwap();
        }

        function state(value) {
            status.setAttribute('data-state', value);
            container.hidden = value !== 'ready';
            active.summary.hidden = value !== 'ready';
            container.setAttribute('aria-busy', String(value === 'loading'));
            status.replaceChildren();
            status.textContent = value === 'loading' ? 'Loading scan results…' : '';
            if (value === 'error') {
                status.textContent = 'Unable to load scan results. ';
                const retry = doc.createElement('button');
                retry.type = 'button';
                retry.className = 'btn btn-default btn-sm';
                retry.textContent = 'Retry';
                retry.addEventListener('click', () => controller.select(keyFor(select.value)));
                status.appendChild(retry);
            }
        }
        const controller = createCache(keyFor(select.value), initial, load, display, state);
        select.addEventListener('change', () => {
            const key = keyFor(select.value);
            const url = new URL(root.location.href);
            url.searchParams.delete('fragment');
            if (key) url.searchParams.set('hostname', key);
            else url.searchParams.delete('hostname');
            root.history.pushState(null, '', url);
            controller.select(key);
        });
        root.addEventListener('popstate', () => {
            const key = (new URL(root.location.href).searchParams.get('hostname') || '').trim().toLowerCase();
            const value = key || '__ip_only__';
            if (!Array.from(select.options).some(option => option.value === value)) {
                root.location.reload();
                return;
            }
            select.value = value;
            controller.select(key);
        });
        return controller;
    }
    const api = {createCache, mount};
    root.PlumHostnameGroups = api;
    if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
