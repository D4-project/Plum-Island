/* Explicit live DNS checks, with a bounded request queue and stale-run protection. */
(function (root) {
    'use strict';
    function mount(button, progress, timeline, endpoint, csrf, fetcher = root.fetch.bind(root)) {
        let running = false, generation = 0;
        const aborters = new Set();
        const pendingNames = new Set();
        button.disabled = !timeline.targets.length;
        async function run() {
            if (running || !timeline.targets.length) return;
            running = true;
            button.disabled = true;
            button.setAttribute('aria-busy', 'true');
            const current = ++generation;
            const queue = timeline.targets.slice();
            let completed = 0;
            progress.textContent = `Resolving 0/${queue.length}…`;
            queue.forEach(target => {
                pendingNames.add(target.hostname);
                timeline.setResult(target.hostname, {status: 'pending'});
            });
            async function worker() {
                while (queue.length && current === generation) {
                    const target = queue.shift();
                    const aborter = new AbortController();
                    aborters.add(aborter);
                    // Browser deadline includes request/response transfer, not only DNS.
                    const timer = setTimeout(() => aborter.abort(), 15000);
                    let result;
                    try {
                        const response = await fetcher(endpoint, {method: 'POST', credentials: 'same-origin',
                            headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf},
                            body: JSON.stringify({token: target.token}), signal: aborter.signal});
                        const payload = await response.json();
                        if (!response.ok && !(response.status === 429 && payload.status === 'busy')) {
                            throw new Error(payload.error || `Resolution failed (${response.status})`);
                        }
                        if (payload.hostname !== target.hostname) throw new Error('Unexpected resolution response');
                        result = payload;
                    } catch (error) {
                        result = {status: error.name === 'AbortError' ? 'timeout' : 'error', error: error.message};
                    } finally {
                        clearTimeout(timer);
                        aborters.delete(aborter);
                    }
                    if (current !== generation) return;
                    pendingNames.delete(target.hostname);
                    timeline.setResult(target.hostname, result);
                    completed += 1;
                    progress.textContent = `Resolved ${completed}/${timeline.targets.length}`;
                }
            }
            try {
                await Promise.all(Array.from({length: Math.min(4, queue.length)}, worker));
            } finally {
                if (current === generation) {
                    running = false;
                    button.disabled = false;
                    button.setAttribute('aria-busy', 'false');
                }
            }
        }
        button.addEventListener('click', run);
        function cancel() {
            generation += 1;
            aborters.forEach(aborter => aborter.abort());
            aborters.clear();
            pendingNames.forEach(hostname => timeline.setResult(hostname, {status: 'cancelled'}));
            pendingNames.clear();
            if (running) progress.textContent = 'Resolution cancelled — click Active DNS to retry';
            running = false;
            button.disabled = !timeline.targets.length;
            button.setAttribute('aria-busy', 'false');
        }
        function destroy() {
            cancel();
            button.removeEventListener('click', run);
        }
        return {run, cancel, destroy};
    }
    root.PlumPdnsResolve = {mount};
    if (typeof module !== 'undefined') module.exports = {mount};
})(typeof window === 'undefined' ? globalThis : window);
