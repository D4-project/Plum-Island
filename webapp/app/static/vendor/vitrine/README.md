# Vitrine components (vt-json, vt-terminal)

Source: https://github.com/ecrou-exact/vitrine (MIT), build v0.14.0.
Documentation: https://ecrou-exact.github.io/vitrine/docs.html

`esm/vt-json.js`, `esm/vt-terminal.js` and their shared ESM chunks were copied
from the project's official deployed build (`/dist/esm/`) on 2026-11-19; both
components come from the same build. `manifest.json` records the exact source
URLs and SHA-256 hashes of this local snapshot. `LICENSE` and
`THIRD_PARTY_NOTICES.md` are the upstream files. Bundled files are unmodified.

- `vt-json`: the two scan-search pages (scan report viewer).
- `vt-terminal`: IP detail WHOIS panel, WHOIS text passed through the
  `content` property (text only, never a remote `src`).

Both receive the Plum color mode through their `theme` attribute
(`app/static/themes/plum/color_mode.js`). If a component cannot load, the
inline JSON / plain `<pre>` stays readable with the fallback styles in
`appbuilder/css/themes/plum-components.css`.

To update, replace `esm/` with both entry files and all their relative module
dependencies from a single upstream build, update the manifest and license
files, then check JSON tree/raw views, copy/search controls, scan-result
expansion, the WHOIS terminal and light/dark modes.
