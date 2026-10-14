/* Passive DNS shares the port timeline renderer, never the scan filter/domain. */
(function (root) {
    'use strict';
    function mount(doc, container, records) {
        const timeline = root.PlumPortTimeline;
        const entries = [];
        let controller = null;
        const axisRow = doc.createElement('div');
        axisRow.className = 'ip-pdns-timeline-row ip-pdns-axis-row';
        const progress = doc.createElement('div');
        progress.id = 'ip-pdns-resolve-progress';
        progress.className = 'text-muted';
        progress.setAttribute('role', 'status');
        progress.setAttribute('aria-live', 'polite');
        axisRow.appendChild(progress);
        const axisHost = doc.createElement('div');
        axisHost.style.height = '24px';
        axisRow.appendChild(axisHost);
        container.appendChild(axisRow);
        const gridHost = doc.createElement('div');
        gridHost.className = 'ip-pdns-shared-grid';
        container.appendChild(gridHost);
        function select(selected) {
            entries.forEach(entry => {
                entry.card.classList.toggle('active', entry === selected);
                entry.items[0].link.setAttribute('aria-pressed', String(entry === selected));
            });
            if (controller) controller.sync();
        }
        records.filter(record => record && typeof record === 'object' && !Array.isArray(record)).forEach((record, index) => {
            const row = doc.createElement('div');
            row.className = 'ip-pdns-row ip-pdns-timeline-row';
            const label = doc.createElement('button');
            label.type = 'button';
            label.className = 'ip-pdns-record-label';
            const value = record.rdata === null || record.rdata === undefined ? 'N/A' : String(record.rdata);
            const type = record.rrtype === null || record.rrtype === undefined ? '?' : String(record.rrtype);
            label.textContent = `${value} (${type})`;
            label.title = `RRName: ${String(record.rrname || 'N/A')} | Count: ${String(record.count ?? 'N/A')}`;
            const host = doc.createElement('div');
            host.className = 'ip-port-timeline';
            host.id = `pdns-timeline-${index}`;
            label.setAttribute('aria-controls', host.id);
            host.setAttribute('aria-label', `Passive DNS history: ${value} (${type})`);
            const first = timeline.timestamp(record.time_first);
            const last = timeline.timestamp(record.time_last);
            row.setAttribute('data-first-seen', first === null ? '' : first);
            row.setAttribute('data-last-seen', last === null ? '' : last);
            const entry = {card: row, host, items: [{tab: row, link: label, range: timeline.interval(first, last)}]};
            entry.hostname = String(record.rrtype).toUpperCase() === 'A' ? record.resolve_hostname : null;
            entry.token = record.resolve_token;
            entry.status = doc.createElement('span');
            entry.status.className = 'ip-pdns-resolution-status';
            if (entry.hostname && entry.token) label.appendChild(entry.status);
            label.addEventListener('click', () => select(entry));
            entries.push(entry);
            row.appendChild(label);
            row.appendChild(host);
            container.appendChild(row);
        });
        const latest = entries.reduce((selected, entry) => {
            const end = entry.items[0].range?.end ?? -Infinity;
            const previous = selected?.items[0].range?.end ?? -Infinity;
            return selected === null || end > previous ? entry : selected;
        }, null);
        select(latest);
        controller = timeline.mount(doc, entries, {compact: true, axisHost, gridHost, container});
        const messages = {pending: 'Resolving…', matched: '', mismatch: 'No longer resolves to this IP',
            nxdomain: 'Name does not exist', no_answer: 'No A answer', timeout: 'DNS timeout — retry',
            error: 'DNS lookup failed — retry', busy: 'Resolver busy — retry', cancelled: 'Cancelled — retry'};
        const targets = new Map();
        const groups = new Map();
        entries.forEach(entry => {
            if (typeof entry.hostname === 'string' && typeof entry.token === 'string') {
                targets.set(entry.hostname, {hostname: entry.hostname, token: entry.token});
                if (!groups.has(entry.hostname)) groups.set(entry.hostname, []);
                groups.get(entry.hostname).push(entry);
            }
        });
        let refreshFrame = null;
        function setResult(hostname, result) {
            (groups.get(hostname) || []).forEach(entry => {
                const date = timeline.timestamp(result.checked_at);
                const matched = result.status === 'matched' && date !== null;
                entry.items[0].verifiedAt = matched ? date : null;
                entry.status.textContent = messages[result.status] ?? messages.error;
                entry.status.title = result.error || (date === null ? '' :
                    `Checked: ${new Date(date * 1000).toISOString().slice(0, 19).replace('T', ' ')} UTC`);
            });
            if (root.requestAnimationFrame) {
                if (refreshFrame === null) refreshFrame = root.requestAnimationFrame(() => {
                    refreshFrame = null;
                    controller.refresh();
                });
            } else controller.refresh();
        }
        function destroy() {
            if (refreshFrame !== null) root.cancelAnimationFrame(refreshFrame);
            controller.destroy();
        }
        return {...controller, destroy, targets: Array.from(targets.values()), setResult};
    }
    root.PlumPdnsTimeline = {mount};
    if (typeof module !== 'undefined') module.exports = {mount};
})(typeof window === 'undefined' ? globalThis : window);
