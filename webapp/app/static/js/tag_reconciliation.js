/* Shared CLI/GUI reconciliation progress. Rendering never starts a job. */
(function () {
    'use strict';
    const root = document.querySelector('[data-tag-reconciliation]');
    if (!root) return;
    const status = root.querySelector('[data-index-status]');
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
    async function poll() {
        try {
            const response = await fetch(root.dataset.statusUrl, {cache: 'no-store'});
            if (!response.ok) throw new Error('Status unavailable');
            const data = await response.json();
            const complete = data.phase === 'up_to_date' || data.phase === 'done';
            const measurable = ['scanning', 'reparsing', 'retagging'].includes(data.phase) && Number(data.total) > 0;
            const percent = complete ? 100 : measurable
                ? Math.min(99, Math.floor(Number(data.processed) * 100 / Number(data.total))) : null;
            status.textContent = labels[data.phase] || 'Checking detection updates';
            const notes = [];
            if (data.revision) notes.push('Revision ' + data.revision);
            if (measurable) notes.push(data.processed + '/' + data.total + ' captures');
            if (data.pending_changes) notes.push(data.pending_changes + ' additional rule changes pending');
            const pacing = data.pacing || {};
            if (data.phase === 'planning' && Number.isFinite(pacing.candidates)) {
                notes.push(pacing.candidates + ' captures identified');
            }
            if (!complete && ['foreground', 'quiet'].includes(pacing.mode)) {
                notes.push('Waiting for search and ingestion activity to settle');
            } else if (!complete && pacing.mode === 'idle_boost') {
                notes.push('Running faster while the system is idle');
            }
            if (pacing.comparable_samples > 0 && Number.isFinite(pacing.observed_degradation)) {
                const change = Math.round(pacing.observed_degradation * 100);
                notes.push('Latest comparable search: ' + (change > 0 ? '+' : '') + change + '%');
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
            bar.removeAttribute('aria-valuenow');
        } finally {
            window.setTimeout(poll, 3000);
        }
    }
    poll();
})();
