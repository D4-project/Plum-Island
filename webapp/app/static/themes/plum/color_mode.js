/* Plum-only color preference. Apply before the body renders to avoid a flash. */
(function () {
    'use strict';
    const key = 'plum.color-mode';
    const root = document.documentElement;
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    let mode;

    function savedMode() {
        try {
            const value = window.localStorage.getItem(key);
            return value === 'dark' || value === 'light' ? value : null;
        } catch (_error) {
            return null;
        }
    }

    let preferred = savedMode();

    function syncViewers(container) {
        if (container.matches && container.matches('vt-json')) {
            container.setAttribute('theme', mode);
        }
        if (container.querySelectorAll) {
            container.querySelectorAll('vt-json').forEach(viewer => viewer.setAttribute('theme', mode));
        }
    }

    function apply(value) {
        mode = value;
        root.setAttribute('data-plum-color-mode', mode);
        const button = document.getElementById('plum-color-mode-toggle');
        if (button) {
            button.setAttribute('aria-pressed', String(mode === 'dark'));
            button.title = mode === 'dark' ? 'Use light mode' : 'Use dark mode';
        }
        syncViewers(document);
    }

    apply(preferred || (system.matches ? 'dark' : 'light'));

    document.addEventListener('DOMContentLoaded', function () {
        apply(mode);
        const button = document.getElementById('plum-color-mode-toggle');
        if (button) {
            button.addEventListener('click', function () {
                preferred = mode === 'dark' ? 'light' : 'dark';
                apply(preferred);
                try {
                    window.localStorage.setItem(key, mode);
                } catch (_error) {
                    // The toggle remains usable when browser storage is unavailable.
                }
            });
        }
        new MutationObserver(records => {
            records.forEach(record => record.addedNodes.forEach(syncViewers));
        }).observe(root, {childList: true, subtree: true});
    });

    const followSystem = () => {
        if (!preferred) apply(system.matches ? 'dark' : 'light');
    };
    if (system.addEventListener) system.addEventListener('change', followSystem);
    else system.addListener(followSystem);

    window.addEventListener('storage', event => {
        if (event.key === key || event.key === null) {
            preferred = savedMode();
            apply(preferred || (system.matches ? 'dark' : 'light'));
        }
    });
})();
