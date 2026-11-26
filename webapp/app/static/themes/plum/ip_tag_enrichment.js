(function (global) {
    'use strict';

    const DEFAULT_BATCH_SIZE = 5;
    const MAX_CONCURRENT_BATCHES = 4;
    const badgeRowObservers = new WeakMap();

    function fitBadgeRow(target) {
        if (!target || target.hidden || target.clientWidth <= 0) {
            return;
        }
        const badges = [...target.children].filter(
            (badge) => !badge.classList.contains('search-ip-more')
        );
        if (target.dataset.expanded === 'true') {
            badges.forEach((badge) => badge.style.removeProperty('display'));
            target.querySelector('.search-ip-more')?.remove();
            return;
        }
        let summary = target.querySelector('.search-ip-more');
        if (!summary) {
            summary = document.createElement('button');
            summary.type = 'button';
            summary.className = 'search-ip-more';
            summary.addEventListener('click', () => {
                target.dataset.expanded = 'true';
                target.closest('.search-ip-tags')?.classList.add('is-expanded');
                fitBadgeRow(target);
            });
            target.appendChild(summary);
        }
        badges.forEach((badge) => badge.style.removeProperty('display'));
        summary.style.display = 'none';
        if (badges.length === 0) {
            return;
        }
        const styles = global.getComputedStyle(target);
        const gap = Number.parseFloat(styles.columnGap || styles.gap) || 0;
        const availableWidth = target.clientWidth;
        const fullWidth = badges.reduce(
            (width, badge) => width + badge.getBoundingClientRect().width,
            0
        ) + gap * Math.max(0, badges.length - 1);
        if (fullWidth <= availableWidth) {
            return;
        }

        let visibleCount = 0;
        for (let count = badges.length - 1; count >= 0; count -= 1) {
            summary.textContent = `+${badges.length - count} more`;
            summary.style.removeProperty('display');
            const shownWidth = badges
                .slice(0, count)
                .reduce((width, badge) => width + badge.getBoundingClientRect().width, 0);
            const neededWidth = shownWidth + summary.getBoundingClientRect().width
                + gap * count;
            if (neededWidth <= availableWidth) {
                visibleCount = count;
                break;
            }
            summary.style.display = 'none';
        }
        badges.slice(visibleCount).forEach((badge) => {
            badge.style.display = 'none';
        });
        summary.textContent = `+${badges.length - visibleCount} more`;
        summary.style.removeProperty('display');
    }

    global.fitSearchBadgeRow = function fitSearchBadgeRow(target) {
        if (!target) {
            return;
        }
        if (typeof ResizeObserver !== 'undefined' && !badgeRowObservers.has(target)) {
            const observer = new ResizeObserver(() => fitBadgeRow(target));
            observer.observe(target);
            badgeRowObservers.set(target, observer);
        }
        global.requestAnimationFrame(() => fitBadgeRow(target));
    };

    function normalizeTag(value) {
        let normalized = String(value || '').trim().toLowerCase();
        while (normalized.startsWith('tag:') && normalized.split(':').length >= 3) {
            normalized = normalized.slice(4).trim();
        }
        return normalized;
    }

    global.renderIpTagBadges = function renderIpTagBadges(target, tags) {
        if (!target) {
            return;
        }
        target.replaceChildren();
        for (const tag of tags) {
            const badge = document.createElement('span');
            const prefix = tag.split(':', 1)[0];
            const prefixClass = {
                vuln: 'ip-detail-tag-vuln',
                vendor: 'ip-detail-tag-vendor',
                product: 'ip-detail-tag-product',
                type: 'ip-detail-tag-type',
                proto: 'ip-detail-tag-proto',
                lang: 'ip-detail-tag-lang',
                cpe: 'ip-detail-tag-cpe',
                hard: 'ip-detail-tag-cpe'
            }[prefix] || '';
            badge.className = `ip-detail-tag search-ip-tag ${prefixClass}`.trim();
            badge.title = tag;
            const separator = tag.indexOf(':');
            if (separator > 0) {
                const namespace = document.createElement('span');
                namespace.className = 'plum-tag-namespace';
                namespace.textContent = tag.slice(0, separator + 1);
                badge.appendChild(namespace);
            }
            const value = document.createElement('span');
            value.className = 'plum-tag-value';
            value.textContent = separator > 0 ? tag.slice(separator + 1) : tag;
            badge.appendChild(value);
            target.appendChild(badge);
        }
        target.hidden = tags.length === 0;
        global.fitSearchBadgeRow(target);
    };

    global.createIpTagEnricher = function createIpTagEnricher(options) {
        const settings = options || {};
        const pendingIps = new Set();
        const resolvedIps = new Set();
        let timer = null;
        const controllers = new Set();
        let generation = 0;
        let timeRange = {fromTs: null, toTs: null};

        function schedule() {
            if (timer || controllers.size >= MAX_CONCURRENT_BATCHES || pendingIps.size === 0) {
                return;
            }
            timer = setTimeout(() => {
                timer = null;
                processQueue();
            }, 0);
        }

        function processQueue() {
            if (controllers.size >= MAX_CONCURRENT_BATCHES || pendingIps.size === 0) {
                return;
            }
            const requestGeneration = generation;
            const batch = [...pendingIps].slice(0, settings.batchSize || DEFAULT_BATCH_SIZE);
            batch.forEach((ip) => pendingIps.delete(ip));

            const requestController = new AbortController();
            controllers.add(requestController);
            fetch(settings.endpoint || '/kvsearchview/tags', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        ips: batch,
                        from_ts: timeRange.fromTs,
                        to_ts: timeRange.toTs
                    }),
                    signal: requestController.signal
                })
                .then((response) => settings.readJsonResponse(response))
                .then((data) => {
                    if (requestGeneration !== generation) {
                        return;
                    }
                    for (const [ip, rawTags] of Object.entries(data.tags_by_ip || {})) {
                        const tags = [...new Set((rawTags || []).map(normalizeTag).filter(Boolean))]
                            .sort((a, b) => a.localeCompare(b));
                        resolvedIps.add(ip);
                        settings.renderTags(ip, tags);
                        if (settings.renderRequestedHostnames) {
                            settings.renderRequestedHostnames(
                                ip,
                                (data.requested_hostnames_by_ip || {})[ip] || [],
                                (data.ptr_hostnames_by_ip || {})[ip] || []
                            );
                        }
                        if (settings.renderTimestamps) {
                            settings.renderTimestamps(ip, (data.timestamps_by_ip || {})[ip]);
                        }
                    }
                })
                .catch((error) => {
                    if (error?.name !== 'AbortError') {
                        console.warn('Tag lookup failed', error);
                    }
                })
                .finally(() => {
                    controllers.delete(requestController);
                    schedule();
                });
            schedule();
        }

        return {
            queue(results, range) {
                timeRange = {
                    fromTs: range?.from_ts ?? null,
                    toTs: range?.to_ts ?? null
                };
                Object.keys(results || {}).forEach((ip) => {
                    if (!resolvedIps.has(ip)) {
                        pendingIps.add(ip);
                    }
                });
                schedule();
            },
            reset() {
                generation += 1;
                pendingIps.clear();
                resolvedIps.clear();
                if (timer) {
                    clearTimeout(timer);
                    timer = null;
                }
                controllers.forEach((requestController) => requestController.abort());
                controllers.clear();
            },
            abort() {
                controllers.forEach((requestController) => requestController.abort());
            }
        };
    };
}(window));
