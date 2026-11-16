# Vitrine JSON viewer

Source: https://github.com/ecrou-exact/vitrine (MIT).
Documentation: https://ecrou-exact.github.io/vitrine/docs.html?page=components/json

The JSON component and its shared ESM chunks were copied from the project's
official deployed build on 2026-11-12. Upstream did not have a tagged release
at that time. `manifest.json` records the exact source URLs and SHA-256 hashes
of this local snapshot. `LICENSE` and `THIRD_PARTY_NOTICES.md` retain upstream
license information. Bundled files are unmodified.

Only the two scan-search pages load this component. It displays data already
returned by Plum using text content; it is not given a remote `src` URL.
If the component cannot load, the inline JSON supplied by the search page
remains readable with the fallback styles in
`appbuilder/css/themes/plum-components.css`.

To update, replace `esm/vt-json.js` and all its relative module dependencies
from a single upstream build, update the manifest and license files, then
check JSON tree/raw views, copy/search controls and scan-result expansion.
