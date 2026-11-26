/* Shared CLI/GUI reconciliation progress. Rendering never starts a job. */
(function () {
    'use strict';
    const root = document.querySelector('[data-tag-reconciliation]');
    if (!root) return;
    const status = root.querySelector('[data-index-status]');
    const eta = root.querySelector('[data-index-eta]');
    const bar = root.querySelector('[data-index-progress]');
    const detail = root.querySelector('[data-index-detail]');
    const labels = {
        waiting_for_scheduler: 'Waiting for the scheduler',
        queued: 'Detection update queued',
        planning: 'Identifying affected captures',
        scanning: 'Applying detection updates',
        reparsing: 'Updating indexed capture fields',
        retagging: 'Applying changed detection rules',
        catching_up: 'Catching up with incoming captures',
        paused: 'Detection update paused',
        failed: 'Detection update failed — active results retained',
        blocked: 'Detection update blocked — correct the reported rules or configuration',
        up_to_date: 'Detections up to date',
        done: 'Detection update published'
    };
    function formatEta(seconds) {
        if (!Number.isFinite(seconds)) return 'Calculating…';
        if (seconds < 60) return '<1m';
        const minutes = Math.ceil(seconds / 60);
        const hours = Math.floor(minutes / 60);
        return hours ? hours + 'h ' + minutes % 60 + 'm' : minutes + 'm';
    }

    async function poll() {
        try {
            const response = await fetch(root.dataset.statusUrl, {cache: 'no-store'});
            if (!response.ok) throw new Error('Status unavailable');
            const data = await response.json();
            const complete = data.phase === 'up_to_date' || data.phase === 'done';
            const scanning = ['scanning', 'reparsing', 'retagging'].includes(data.phase);
            const measurable = (scanning || data.phase === 'paused') && Number(data.total) > 0;
            const percent = complete ? 100 : measurable
                ? Math.min(99, Math.floor(Number(data.processed) * 100 / Number(data.total))) : null;
            status.textContent = labels[data.phase] || 'Checking detection updates';
            const notes = [];
            if (data.revision) notes.push('Revision ' + data.revision);
            if (measurable) notes.push(data.processed + '/' + data.total + ' captures');
            if (data.pending_changes) notes.push(data.pending_changes + ' additional rule changes pending');
            const pacing = data.pacing || {};
            if (Number(pacing.excluded_sources) > 0) {
                notes.push(pacing.excluded_sources + ' non-public source exclusions encountered');
            }
            if (data.phase === 'planning' && Number.isFinite(pacing.candidates)) {
                notes.push(pacing.candidates + ' captures identified');
            }
            const running = scanning || ['planning', 'catching_up'].includes(data.phase);
            const heartbeat = Math.max(data.heartbeat || 0, pacing.heartbeat || 0);
            const stalled = heartbeat > 0 && Date.now() / 1000 - heartbeat > 120;
            const paused = ['foreground', 'quiet', 'stopped'].includes(pacing.mode);
            const remaining = running && !stalled && !paused
                ? formatEta(scanning ? pacing.eta_seconds : null) : '∞';
            eta.textContent = '· ETA ' + remaining;
            if (running && ['foreground', 'quiet'].includes(pacing.mode)) {
                notes.push('Indexing paused for searches and imports');
            } else if (running && ['limited', 'idle_boost'].includes(pacing.mode)) {
                const readsMeilisearch = pacing.uses_meilisearch || data.phase === 'reparsing';
                const indexingMode = readsMeilisearch ? 'Full Indexing' : 'Fast Indexing';
                if (Number(pacing.slowdown_factor) > 1) {
                    notes.push(indexingMode + ' slowed down to protect search performance');
                } else if (pacing.mode === 'idle_boost') {
                    notes.push(indexingMode);
                } else {
                    notes.push('Indexing in the background');
                }
            }
            if (data.message) notes.push(data.message);
            detail.textContent = notes.join(' · ');
            bar.style.width = (percent === null ? 100 : percent) + '%';
            bar.textContent = percent === null ? '…' : percent + '%';
            bar.classList.toggle('progress-bar-striped', percent === null);
            const failed = ['failed', 'blocked'].includes(data.phase);
            bar.classList.toggle('active', percent === null && !failed);
            bar.classList.toggle('progress-bar-danger', failed);
            if (percent === null) bar.removeAttribute('aria-valuenow');
            else bar.setAttribute('aria-valuenow', String(percent));
        } catch (_error) {
            status.textContent = 'Unable to read detection update status; retrying…';
            eta.textContent = '· ETA ∞';
            bar.removeAttribute('aria-valuenow');
        } finally {
            window.setTimeout(poll, 3000);
        }
    }
    poll();
})();
