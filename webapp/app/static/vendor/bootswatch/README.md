# Readable stylesheet used by Plum

Bootswatch Readable 3.4.1, based on Bootstrap 3.4.1. Copied from the assets
distributed with Flask-AppBuilder 4.8.1 on 2026-11-17. The original copyright
headers are retained; see LICENSE and BOOTSTRAP-LICENSE.

Source: https://github.com/thomaspark/bootswatch/tree/v3.4.1/readable

Local changes:

- Replace the Google Fonts import with `../raleway/raleway.css`.
- Resolve Glyphicons URLs against Flask-AppBuilder's locally served fonts at
  `/static/appbuilder/fonts/` instead of the incorrect relative `css/fonts/` path.

Plum imports this copy. Other configured themes retain their existing assets.
When updating it, preserve these local URL changes and run the offline asset
tests. The upstream URLs above document provenance and are not runtime requests.
