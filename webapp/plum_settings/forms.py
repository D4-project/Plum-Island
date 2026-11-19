"""Strict form decoding and presentation without exposing stored credentials."""

from .registry import SECTIONS, SETTINGS, SettingsError, default_value, parse_value
from .store import WEBAPP_DIR


def overrides_from_form(form, desired, baseline):
    """Accept only declared controls; retain secrets unless explicitly replaced."""
    allowed = {"csrf_token", "revision"}
    for key, field in SETTINGS.items():
        if field.inactive:
            continue
        if field.secret:
            allowed.update({f"secret_action_{key}", f"secret_value_{key}"})
        else:
            allowed.update({key, f"reset_{key}", f"prefilled_{key}"})
    if set(form) - allowed or any(len(values) != 1 for _, values in form.lists()):
        raise SettingsError("The form contains unsupported or repeated fields.")
    current = {**baseline, **desired["overrides"]}
    overrides = dict(desired["overrides"])
    for key, field in SETTINGS.items():
        if field.inactive:
            continue
        if field.secret:
            _secret_override(form, field, overrides)
        elif form.get(f"reset_{key}") == "true":
            overrides.pop(key, None)
        elif key in form:
            changed, parsed = _changed_value(form, field, current)
            if changed:
                overrides[key] = parsed
    return overrides


def _changed_value(form, field, current):
    """Keep untouched defaults inherited while recognizing deliberate edits."""
    key = field.key
    if key not in current and form[key] == "":
        return False, None
    parsed = parse_value(field, form[key])
    marker = form.get(f"prefilled_{key}")
    if marker not in (None, "true", "false"):
        raise SettingsError("The form contains an invalid default marker.")
    if (
        key not in current
        and marker == "true"
        and parsed == default_value(field, WEBAPP_DIR)
    ):
        return False, None
    return key not in current or parsed != current[key], parsed


def _secret_override(form, field, overrides):
    action = form.get(f"secret_action_{field.key}", "keep")
    value = form.get(f"secret_value_{field.key}", "")
    if action == "keep":
        if value:
            raise SettingsError(
                f"{field.key}: choose Replace to save a new credential."
            )
    elif action == "replace":
        overrides[field.key] = parse_value(field, value)
    elif action == "clear" and field.optional:
        overrides[field.key] = ""
    elif action == "base":
        overrides.pop(field.key, None)
    else:
        raise SettingsError(f"{field.key}: choose a supported credential action.")


def display_value(field, value):
    """Render booleans, suffix lists and explicit empty defaults consistently."""
    if field.kind == "suffixes" and value is not None:
        return "\n".join(value)
    return str(value) if value is not None else ""


def cards_for(runtime, desired):
    """Build template data with no current, saved or applied secret values."""
    values = {**runtime.baseline, **desired["overrides"]}
    applied = runtime.applied
    pending = set(runtime.pending(desired))
    cards = []
    for section in SECTIONS:
        fields = []
        for field in section.fields:
            value = values.get(field.key, default_value(field, WEBAPP_DIR))
            fields.append(
                {
                    "definition": field,
                    "value": "" if field.secret else display_value(field, value),
                    "applied": (
                        ""
                        if field.secret
                        else (
                            display_value(field, applied[field.key])
                            if field.key in applied
                            else "Not explicitly configured"
                        )
                    ),
                    "inherited": field.key not in values,
                    "configured": bool(value) if field.secret else False,
                    "default": display_value(field, default_value(field, WEBAPP_DIR))
                    or "Not set",
                    "override": field.key in desired["overrides"],
                    "pending": field.key in pending,
                }
            )
        cards.append({"section": section, "fields": fields})
    return cards
