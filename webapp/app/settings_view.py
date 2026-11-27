"""Administrator-only configuration page with explicit restart semantics."""

from flask import abort, current_app, flash, make_response, redirect, request, url_for
from flask_appbuilder import BaseView, expose, has_access
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError

from plum_settings.forms import cards_for, overrides_from_form
from plum_settings.registry import SettingsError
from plum_settings.store import SettingsConflict


def settings_template_context():
    """Expose only restart status to shared page chrome, never configuration values."""
    runtime = current_app.config.get("PLUM_SETTINGS_RUNTIME")
    if runtime is None:
        return {}
    try:
        pending = bool(runtime.pending(runtime.store.desired()))
    except SettingsError:
        # A damaged configuration must not prevent unrelated pages from rendering.
        return {"plum_settings_unavailable": True}
    return {"plum_restart_pending": pending}


class PlumSettingsView(BaseView):
    """Keep configuration access restricted even if FAB grants are misassigned."""

    route_base = "/plumsettings"
    default_view = "index"
    base_permissions = ["can_index"]

    @expose("/", methods=["GET", "POST"])
    @has_access
    def index(self):
        """Show the saved revision or commit a validated, CSRF-protected update."""
        if not self.appbuilder.sm.is_plum_settings_admin():
            abort(403)
        runtime = current_app.config["PLUM_SETTINGS_RUNTIME"]
        error = None
        desired = None
        status = 200
        try:
            desired = runtime.store.desired()
            if request.method == "POST":
                validate_csrf(request.form.get("csrf_token"))
                overrides = overrides_from_form(request.form, desired, runtime.baseline)
                updated = runtime.store.save(
                    request.form.get("revision"), overrides, runtime.baseline
                )
                if runtime.pending(updated):
                    flash(
                        "Settings saved. Restart Plum-Island to apply changes.",
                        "info",
                    )
                else:
                    flash(
                        "Settings saved. No pending changes.",
                        "success",
                    )
                return self._private_response(
                    redirect(url_for("PlumSettingsView.index"))
                )
        except SettingsConflict as problem:
            error, status = str(problem), 409
        except (SettingsError, ValidationError) as problem:
            error, status = str(problem), 400
        if desired is None:
            return self._private_response(
                self.render_template(
                    "plum_settings.html", cards=[], error=error, unavailable=True
                ),
                status,
            )
        cards = cards_for(runtime, desired)
        db_titles = {"Connectivity to Meilisearch", "Connectivity to Kvrocks"}
        external_titles = {"Passive DNS", "Geolocation", "BGP Information"}
        grouped_titles = db_titles | external_titles
        db_cards = [card for card in cards if card["section"].title in db_titles]
        external_cards = [
            card for card in cards if card["section"].title in external_titles
        ]
        tabs = [
            {
                "title": "Database Connections",
                "cards": db_cards,
                "field_count": sum(len(card["fields"]) for card in db_cards),
            },
            {
                "title": "External Services",
                "cards": external_cards,
                "field_count": sum(len(card["fields"]) for card in external_cards),
            },
        ]
        tabs.extend(
            {
                "title": card["section"].title,
                "cards": [card],
                "field_count": len(card["fields"]),
            }
            for card in cards
            if card["section"].title not in grouped_titles
        )
        valid_sections = {
            f"settings-section-{index}" for index in range(1, len(tabs) + 1)
        }
        active_section = (
            request.form.get("active_section") if request.method == "POST" else None
        )
        if active_section not in valid_sections:
            active_section = "settings-section-1" if tabs else ""
        return self._private_response(
            self.render_template(
                "plum_settings.html",
                tabs=tabs,
                error=error,
                unavailable=False,
                revision=desired["revision"],
                pending=runtime.pending(desired),
                active_section=active_section,
            ),
            status,
        )

    @staticmethod
    def _private_response(body, status=200):
        """Prevent configuration values from entering shared or browser caches."""
        response = (
            make_response(body, status)
            if isinstance(body, str)
            else make_response(body)
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
        return response
