(() => {
    const indexedReportUrl = document.currentScript.dataset.indexedReportUrl;

    function render(container, report, label = 'Scan report') {
        const viewer = document.createElement('vt-json');
        viewer.setAttribute('variant', 'full');
        viewer.setAttribute('view', 'tree');
        viewer.setAttribute('depth', '1000');
        viewer.setAttribute('theme', document.documentElement.dataset.plumColorMode || 'light');
        viewer.setAttribute('label', label);
        viewer.textContent = JSON.stringify(report, null, 2);
        container.replaceChildren(viewer);
    }

    async function toggleIndexed(link) {
        const target = document.getElementById(link.dataset.target);
        target.hidden = !target.hidden;
        link.setAttribute('aria-expanded', String(!target.hidden));
        if (target.hidden || target.querySelector('vt-json') || target.dataset.loading) return;

        target.dataset.loading = 'true';
        target.textContent = 'Loading scan report…';
        try {
            const url = new URL(indexedReportUrl, window.location.href);
            url.searchParams.set('uid', link.dataset.uid);
            const response = await fetch(url, {headers: {Accept: 'application/json'}});
            if (!response.ok) throw new Error('Scan report unavailable');
            render(target, await response.json());
        } catch (error) {
            target.textContent = 'Scan report unavailable.';
        } finally {
            delete target.dataset.loading;
        }
    }

    function appendReport(container, title, report, hostnames = []) {
        const details = document.createElement('details');
        details.className = 'panel panel-default';
        const summary = document.createElement('summary');
        summary.className = 'panel-heading';
        summary.textContent = title;
        if (hostnames.length) {
            const names = document.createElement('small');
            names.className = 'text-muted';
            names.textContent = ` · ${hostnames.join(', ')}`;
            summary.appendChild(names);
        }
        const body = document.createElement('div');
        body.className = 'panel-body';
        details.append(summary, body);
        details.addEventListener('toggle', () => {
            if (details.open && !body.firstChild) render(body, report, title);
        });
        container.appendChild(details);
    }

    async function loadJobReport(container) {
        try {
            const response = await fetch(container.dataset.jobReportUrl, {
                headers: {Accept: 'application/json'}
            });
            if (response.status === 404) {
                container.textContent = 'No saved result for this job.';
                return;
            }
            if (!response.ok) throw new Error('Job report unavailable');
            const report = await response.json();
            const hosts = Array.isArray(report) ? report : [report];
            container.textContent = hosts.length ? '' : 'No open ports reported.';
            for (const host of hosts) {
                if (typeof host?.addr !== 'string') continue;
                const names = Array.isArray(host.hostnames) ? host.hostnames : [];
                const hostnames = names.filter(entry => typeof entry?.name === 'string')
                    .map(({name, type}) => type === 'PTR' ? `${name} (PTR)` : name);
                appendReport(container, host.addr, host, hostnames);
            }
            appendReport(container, 'Full report', report);
        } catch (error) {
            container.textContent = 'Could not load the job report.';
        }
    }

    window.PlumScanReport = {render, toggleIndexed};
    document.querySelectorAll('[data-job-report-url]').forEach(loadJobReport);
})();
