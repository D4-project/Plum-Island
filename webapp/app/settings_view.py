"""Administrator-only configuration page with explicit restart semantics."""

from flask import abort, current_app, flash, make_response, redirect, request, url_for
from flask_appbuilder import BaseView, expose, has_access
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError

from plum_settings.forms import cards_for, overrides_from_form
from plum_settings.registry import SettingsError
from plum_settings.store import SettingsConflict


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
                        "Settings saved. Restart required; affected components are listed "
                        "beside each pending field. No process was restarted.",
                        "info",
                    )
                else:
                    flash(
                        "Settings saved. No changes are pending in this web process.",
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
        return self._private_response(
            self.render_template(
                "plum_settings.html",
                cards=cards_for(runtime, desired),
                error=error,
                unavailable=False,
                revision=desired["revision"],
                pending=runtime.pending(desired),
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
