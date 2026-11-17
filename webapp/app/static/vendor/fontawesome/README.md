# Font Awesome Free 6.7.2

Unmodified official CSS, v4 compatibility aliases and matching solid, regular and
brand webfonts from https://github.com/FortAwesome/Font-Awesome/tree/6.7.2.
Upstream Git revision: `af620534bfc3c2d4cbefcfeec29603bbe7809e64`.

`app/ui_assets.py` serves these files at Flask-AppBuilder's existing
`/static/appbuilder/css/fontawesome/` and `/static/appbuilder/css/webfonts/` URLs.
Both WOFF2 and the upstream TrueType fallback are included. All application
UI themes use the same version; no remote font service is required.

Flask-AppBuilder 4.8.1 bundles Font Awesome 6.2.1, whose solid glyph U+F87D has
incorrect bounds. Font Awesome reports this Firefox warning fixed since 6.5:
https://github.com/FortAwesome/Font-Awesome/issues/19925.

Files were downloaded from GitHub's contents API at tag `6.7.2`. Keep CSS and
fonts at the same version when updating, retain `LICENSE.txt` and check Firefox
and Chromium, legacy `.fa` aliases, brands, regular/solid icons, and light/dark
modes. Use a fresh cache or reload cached static assets after deployment.

Licenses: fonts SIL OFL 1.1; CSS MIT; icon artwork CC BY 4.0. Full upstream terms
are in `LICENSE.txt`; copyright and license headers remain in each CSS file.
