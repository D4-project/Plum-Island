/* IP detail Informations tab: "Location" map card.
 * Tiles: CIRCL-hosted OpenStreetMap.
 * Position: WHOIS "geoloc:" when present, else CIRCL geolookup country average.
 * The marker popup shows WHOIS network/organisation/address. */
(function () {
    /* Local country flag (vendor/flag-icons, 4:3 SVG); hidden when unknown. */
    const script = document.currentScript;
    const base = script ? new URL('../vendor/flag-icons/4x3/', script.src).href : '';
    window.PlumFlag = function (iso) {
        const img = document.createElement('img');
        img.className = 'plum-flag';
        img.alt = '';
        img.width = 20;
        img.height = 15;
        img.addEventListener('error', () => { img.hidden = true; });
        if (base && /^[A-Za-z]{2}$/.test(iso || '')) {
            img.src = `${base}${iso.toLowerCase()}.svg`;
        } else {
            img.hidden = true;
        }
        return img;
    };
})();

(function () {
    const config = document.getElementById('ip-map-config');
    const tab = document.querySelector('a[href="#ip-informations"]');
    const results = document.getElementById('ip-info-results');
    if (!config || !results) return;
    const WORLD = [[-85, -180], [85, 180]];
    let map = null;

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function card(extraClass, titleText) {
        const wrapper = el('div', `ip-info-entry ${extraClass}`);
        const title = el('div', 'ip-info-title');
        title.appendChild(el('span', '', titleText));
        const box = el('div', 'ip-info-box');
        wrapper.append(title, box);
        results.appendChild(wrapper);
        return { wrapper, title, box };
    }

    function getJson(url) {
        return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
            .then((response) => {
                if (!response.ok) throw new Error(`Lookup failed (${response.status})`);
                return response.json();
            });
    }

    function countryLocation(payload) {
        const entries = Array.isArray(payload) ? payload : [payload];
        for (const entry of entries) {
            const info = (entry && entry.country_info) || {};
            const lat = parseFloat(info['Latitude (average)']);
            const lon = parseFloat(info['Longitude (average)']);
            if (Number.isFinite(lat) && Number.isFinite(lon)) {
                return { lat, lon, country: info.Country || '', iso: (entry.country && entry.country.iso_code) || info['Alpha-2 code'] || '' };
            }
        }
        return null;
    }

    /* "key: value" lines of a WHOIS answer; first value wins, addresses accumulate. */
    function parseWhois(text) {
        const fields = {};
        (text || '').split(/\r?\n/).forEach((line) => {
            const match = /^\s*([A-Za-z-]+):\s*(.+?)\s*$/.exec(line);
            if (!match) return;
            const key = match[1].toLowerCase();
            if (key === 'address') {
                (fields.address = fields.address || []).push(match[2]);
            } else if (!(key in fields)) {
                fields[key] = match[2];
            }
        });
        return fields;
    }

    function whoisRows(fields) {
        const pick = (...keys) => keys.map((k) => fields[k]).find(Boolean) || '';
        const address = (fields.address || []).join(', ')
            || [pick('city'), pick('stateprov'), pick('postalcode')].filter(Boolean).join(', ');
        return [
            ['Network', pick('netname', 'nethandle')],
            ['Range', pick('inetnum', 'netrange', 'inet6num')],
            ['CIDR', pick('cidr', 'route', 'route6')],
            ['Organisation', pick('org-name', 'orgname', 'descr', 'owner')],
            ['Address', address],
            ['Country', pick('country')],
            ['Abuse contact', pick('abuse-mailbox', 'orgabuseemail', 'abuse-c')],
            ['Registry status', pick('status', 'nettype')],
            ['Last modified', pick('last-modified', 'updated')],
        ].filter(([, value]) => value).map(([field, value]) => ({ field, value }));
    }

    function whoisGeoloc(fields) {
        const match = /^(-?\d+(?:\.\d+)?)[\s,]+(-?\d+(?:\.\d+)?)$/.exec(fields.geoloc || '');
        if (!match) return null;
        const lat = parseFloat(match[1]);
        const lon = parseFloat(match[2]);
        return Math.abs(lat) <= 90 && Math.abs(lon) <= 180 ? { lat, lon } : null;
    }


    function popupContent(rows, country, iso) {
        const box = el('div');
        const head = el('div');
        head.append(window.PlumFlag(iso), el('strong', '', config.dataset.ip));
        box.appendChild(head);
        const shown = rows.filter((r) => ['Network', 'Organisation', 'Address'].includes(r.field));
        if (!shown.length && country) shown.push({ field: 'Country', value: country });
        shown.forEach(({ field, value }) => {
            const line = el('div');
            line.append(el('span', 'text-muted', `${field}: `), document.createTextNode(value));
            box.appendChild(line);
        });
        return box;
    }

    function fullscreenButton(target) {
        const button = el('button', 'btn btn-default btn-xs');
        button.type = 'button';
        button.title = 'Show map full screen';
        button.setAttribute('aria-label', 'Show map full screen');
        const icon = el('i', 'fa fa-expand');
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.addEventListener('click', () => {
            if (document.fullscreenElement === target) {
                document.exitFullscreen();
            } else {
                target.requestFullscreen();
            }
        });
        document.addEventListener('fullscreenchange', () => {
            const active = document.fullscreenElement === target;
            button.title = active ? 'Exit full screen' : 'Show map full screen';
            button.setAttribute('aria-label', button.title);
            icon.className = active ? 'fa fa-compress' : 'fa fa-expand';
            if (map) setTimeout(() => map.invalidateSize(), 50);
        });
        return button;
    }

    function renderMap(location, precise, rows) {
        const { wrapper, title, box } = card('ip-map-entry', 'Location');
        const canvas = el('div', 'ip-map-canvas');
        const note = el('div', 'ip-map-note text-muted', precise
            ? 'Position from the WHOIS "geoloc" field.'
            : `Approximate: centre of ${location.country || 'the country'}, not the exact IP location.`);
        box.append(canvas, note);
        if (typeof window.L === 'undefined') {
            canvas.replaceWith(el('div', 'alert alert-warning', 'Map library failed to load.'));
            return;
        }
        if (document.fullscreenEnabled && wrapper.requestFullscreen) {
            title.appendChild(fullscreenButton(wrapper));
        }
        // Single world copy, no panning past the edges, no endless zoom out.
        map = window.L.map(canvas, {
            minZoom: 2,
            maxBounds: WORLD,
            maxBoundsViscosity: 1.0,
            worldCopyJump: false,
        }).setView([location.lat, location.lon], precise ? 12 : 4);
        window.L.tileLayer('https://geo.circl.lu/hot/{z}/{x}/{y}.png', {
            maxZoom: 18,
            noWrap: true,
            bounds: WORLD,
            // Tiles are rendered on demand by the server (~1s when not cached):
            // keep more tiles around and avoid requesting intermediate levels.
            keepBuffer: 4,
            updateWhenZooming: false,
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors, tiles hosted by CIRCL',
        }).addTo(map);
        window.L.marker([location.lat, location.lon]).addTo(map)
            .bindPopup(popupContent(rows, location.country, location.iso));
    }

    if (tab && window.jQuery) {
        window.jQuery(tab).on('shown.bs.tab', function () {
            if (map) map.invalidateSize();
        });
    }

    window.PlumShowLocation = function (geoData) {
        // Reuse the Whois tab request when available (single WHOIS query per page).
        const whoisData = window.PlumWhoisData
            ? window.PlumWhoisData()
            : config.dataset.whois
                ? getJson(config.dataset.whois)
                : Promise.resolve({ result: '' });
        const whois = whoisData
            .then((data) => parseWhois(data.result))
            .catch(() => ({}));
        Promise.all([geoData.catch(() => null), whois])
            .then(([geo, fields]) => {
                const rows = whoisRows(fields);
                const country = geo ? countryLocation(geo) : null;
                const exact = whoisGeoloc(fields);
                const location = exact
                    ? { ...exact, country: country ? country.country : (fields.country || ''), iso: country ? country.iso : (fields.country || '') }
                    : country;
                if (location) renderMap(location, Boolean(exact), rows);
            });
    };
})();
