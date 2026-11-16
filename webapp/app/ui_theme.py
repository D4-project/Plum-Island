"""Select optional UI templates without changing the original application views."""

from pathlib import Path

from jinja2 import ChoiceLoader, FileSystemLoader


def configure_ui_templates(app):
    """Prefer Plum's template overrides only when its CSS theme is selected.

    Configure this before Flask creates its Jinja environment. Theme changes
    require an application restart, just like other AppBuilder configuration.
    """
    if app.config.get("APP_THEME") != "plum.css":
        return

    original_loader = app.jinja_loader
    theme_directory = Path(app.root_path) / "templates" / "themes" / "plum"
    app.jinja_loader = ChoiceLoader(
        [FileSystemLoader(theme_directory), original_loader]
    )
