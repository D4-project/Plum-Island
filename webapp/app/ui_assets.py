"""Serve the matched local Font Awesome assets at FAB's existing static URLs."""

FONT_AWESOME_CSS = (
    "fontawesome.min.css",
    "regular.min.css",
    "solid.min.css",
    "brands.min.css",
    "v4-shims.min.css",
)
FONT_AWESOME_FONTS = tuple(
    f"{name}.{extension}"
    for name in ("fa-solid-900", "fa-regular-400", "fa-brands-400")
    for extension in ("woff2", "ttf")
)


def configure_icon_assets(app):
    """Override only FAB's known icon assets, retaining theme and URL compatibility.

    FAB 4.8.1 packages FA 6.2.1 fonts with incorrect glyph bounds. Serve the
    unmodified official FA 6.7.2 CSS, fonts and v4 aliases together for every
    theme; the rest of AppBuilder's static blueprint remains unchanged.
    """
    for directory, public_directory, names in (
        ("css", "fontawesome", FONT_AWESOME_CSS),
        ("webfonts", "webfonts", FONT_AWESOME_FONTS),
    ):
        for name in names:
            app.add_url_rule(
                f"/static/appbuilder/css/{public_directory}/{name}",
                endpoint="fontawesome_" + name.replace(".", "_"),
                view_func=app.send_static_file,
                defaults={"filename": f"vendor/fontawesome/{directory}/{name}"},
            )
