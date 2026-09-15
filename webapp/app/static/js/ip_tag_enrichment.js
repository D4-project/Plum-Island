(function (global) {
    'use strict';

    const DEFAULT_BATCH_SIZE = 200;

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
            badge.textContent = tag;
            target.appendChild(badge);
        }
        target.hidden = tags.length === 0;
    };

    global.createIpTagEnricher = function createIpTagEnricher(options) {
        const settings = options || {};
        const pendingIps = new Set();
        const resolvedIps = new Set();
        let timer = null;
        let controller = null;
        let inFlight = false;
        let generation = 0;
        let timeRange = {fromTs: null, toTs: null};

        function schedule() {
            if (timer || inFlight || pendingIps.size === 0) {
                return;
            }
            timer = setTimeout(() => {
                timer = null;
                processQueue();
            }, 0);
        }

        async function processQueue() {
            if (inFlight || pendingIps.size === 0) {
                return;
            }
            const requestGeneration = generation;
            const batch = [...pendingIps].slice(0, settings.batchSize || DEFAULT_BATCH_SIZE);
            batch.forEach((ip) => pendingIps.delete(ip));

            inFlight = true;
            const requestController = new AbortController();
            controller = requestController;
            try {
                const response = await fetch(settings.endpoint || '/kvsearchview/tags', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        ips: batch,
                        from_ts: timeRange.fromTs,
                        to_ts: timeRange.toTs
                    }),
                    signal: requestController.signal
                });
                const data = await settings.readJsonResponse(response);
                if (requestGeneration !== generation) {
                    return;
                }
                for (const [ip, rawTags] of Object.entries(data.tags_by_ip || {})) {
                    const tags = [...new Set((rawTags || []).map(normalizeTag).filter(Boolean))]
                        .sort((a, b) => a.localeCompare(b));
                    resolvedIps.add(ip);
                    settings.renderTags(ip, tags);
                    if (settings.renderTimestamps) {
                        settings.renderTimestamps(ip, (data.timestamps_by_ip || {})[ip]);
                    }
                }
            } catch (error) {
                if (error?.name !== 'AbortError') {
                    console.warn('Tag lookup failed', error);
                }
            } finally {
                if (controller === requestController) {
                    controller = null;
                    inFlight = false;
                    schedule();
                }
            }
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
                if (controller) {
                    controller.abort();
                    controller = null;
                }
                inFlight = false;
            },
            abort() {
                if (controller) {
                    controller.abort();
                }
            }
        };
    };
}(window));
