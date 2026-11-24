"""Private, atomic configuration files and pinned process snapshots."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from .registry import (
    SETTINGS,
    SettingsError,
    default_value,
    parse_value,
    validate_dependencies,
)

WEBAPP_DIR = Path(__file__).resolve().parents[1]


class SettingsConflict(SettingsError):
    """Someone saved a newer version while this form was open."""


def settings_directory():
    """Resolve a deployment-owned location, never a submitted form field."""
    return (
        Path(os.environ.get("PLUM_SETTINGS_DIR", WEBAPP_DIR / ".plum-settings"))
        .expanduser()
        .absolute()
    )


def effective_values(baseline, overrides):
    """Resolve UI defaults separately from the runtime's historical fallbacks."""
    values = {key: default_value(field, WEBAPP_DIR) for key, field in SETTINGS.items()}
    values.update({key: value for key, value in baseline.items() if key in SETTINGS})
    values.update(overrides)
    return values


def _stored_values(record, field):
    """Read known keys, dropping the two provider overrides from the map preview."""
    values = record.get(field)
    if not isinstance(values, dict):
        raise SettingsError("Settings values must be an object.")
    values.pop("MAP_TILE_URL", None)
    values.pop("MAP_TILE_ATTRIBUTION", None)
    if values.keys() - SETTINGS.keys():
        raise SettingsError("Settings file contains unsupported configuration keys.")
    return values


class SettingsStore:
    """Coordinate multiple writers without exposing passwords in errors."""

    def __init__(self, directory=None):
        self.directory = (
            Path(directory) if directory is not None else settings_directory()
        )

    def prepare(self):
        """Require private, owned storage and reject symlink redirection."""
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise SettingsError(
                    "Settings directory must be owned by this service with permissions 0700."
                )
        except OSError:
            raise SettingsError(
                "Cannot access the private settings directory."
            ) from None

    @contextmanager
    def locked(self):
        """Use a stable lock file; replacing the data file cannot bypass it."""
        self.prepare()
        try:
            descriptor = os.open(
                self.directory / "settings.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        except OSError:
            raise SettingsError(
                "Could not save settings; the last valid configuration is retained."
            ) from None

    def read(self, name, missing=None):
        """Read only private regular files; return safe errors for corruption."""
        try:
            descriptor = os.open(self.directory / name, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise SettingsError(
                        "Settings files must be owned by this service with permissions 0600."
                    )
                return json.load(stream)
        except FileNotFoundError:
            if missing is not None:
                return missing
            raise SettingsError(
                "A required settings snapshot is missing; restart the controller before launching workers."
            ) from None
        except (OSError, ValueError):
            raise SettingsError(
                "Cannot read settings. Restore the previous file using the documented offline recovery procedure."
            ) from None

    def write(self, name, document):
        """Flush a private temporary file before atomic replacement."""
        descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, ensure_ascii=True, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.directory / name)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def desired(self):
        """Return the latest validated override revision or the untouched baseline."""
        record = self.read(
            "settings.json", missing={"version": 1, "revision": "0", "overrides": {}}
        )
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or not re.fullmatch(r"0|[a-f0-9]{32}", str(record.get("revision", "")))
        ):
            raise SettingsError(
                "Unsupported settings file format; restore a valid backup."
            )
        overrides = _stored_values(record, "overrides")
        for key, value in overrides.items():
            if SETTINGS[key].inactive:
                raise SettingsError(f"{key} is inactive and cannot be overridden.")
            overrides[key] = parse_value(SETTINGS[key], value)
        return record

    def save(self, expected_revision, overrides, baseline):
        """Commit a complete validated update only if its revision is current."""
        if set(overrides) - SETTINGS.keys():
            raise SettingsError("Unsupported configuration keys.")
        normalized = {}
        for key, value in overrides.items():
            if SETTINGS[key].inactive:
                raise SettingsError(f"{key} is inactive and cannot be edited.")
            normalized[key] = parse_value(SETTINGS[key], value)
        validate_dependencies(effective_values(baseline, normalized))
        with self.locked():
            previous = self.desired()
            if previous["revision"] != expected_revision:
                raise SettingsConflict(
                    "Settings changed in another session. Reload this page before saving again."
                )
            if previous["overrides"] == normalized:
                return previous
            record = {
                "version": 1,
                "revision": uuid.uuid4().hex,
                "overrides": normalized,
            }
            self.write("settings.previous.json", previous)
            self.write("settings.json", record)
            return record

    def snapshot(self, name):
        """Load a named runtime snapshot, with no path traversal or new overrides."""
        if not re.fullmatch(r"runtime-[a-f0-9]{32}\.json", str(name)):
            raise SettingsError("Invalid applied configuration snapshot.")
        record = self.read(name)
        if (
            not isinstance(record, dict)
            or record.get("version") != 1
            or not re.fullmatch(r"0|[a-f0-9]{32}", str(record.get("revision", "")))
        ):
            raise SettingsError("Invalid applied configuration snapshot.")
        _stored_values(record, "values")
        return record


@dataclass
class SettingsRuntime:
    """The configuration this process actually loaded, independent of new saves."""

    store: SettingsStore
    baseline: dict
    applied: dict
    revision: str
    snapshot_name: str

    def pending(self, desired):
        """List field-level differences, including edits reverted to active values."""
        saved = {**self.baseline, **desired["overrides"]}
        unset = object()
        return [
            key
            for key in SETTINGS
            if not SETTINGS[key].inactive
            and saved.get(key, unset) != self.applied.get(key, unset)
        ]


def apply_settings(config):
    """Load at app boot; supervised children use the parent's frozen snapshot."""
    store = SettingsStore()
    baseline = {key: config[key] for key in SETTINGS if key in config}
    inherited = os.environ.get("PLUM_SETTINGS_SNAPSHOT")
    with store.locked():
        if inherited:
            snapshot_name = inherited
            snapshot = store.snapshot(snapshot_name)
        else:
            desired = store.desired()
            if "PDNS_ENABLED" not in baseline:
                legacy = {**baseline, **desired["overrides"]}
                baseline["PDNS_ENABLED"] = bool(
                    str(legacy.get("PASSIVE_USER") or "").strip()
                    and str(legacy.get("PASSIVE_PWD") or "")
                )
            values = dict(baseline)
            values.update(desired["overrides"])
            # No overrides means no new defaults or validation changes for legacy config.py.
            if desired["overrides"]:
                validate_dependencies(effective_values(baseline, desired["overrides"]))
            snapshot_name = f"runtime-{uuid.uuid4().hex}.json"
            snapshot = {"version": 1, "revision": desired["revision"], "values": values}
            store.write(snapshot_name, snapshot)
    for key in SETTINGS:
        config.pop(key, None)
    config.update(snapshot["values"])
    runtime = SettingsRuntime(
        store, baseline, dict(snapshot["values"]), snapshot["revision"], snapshot_name
    )
    config["PLUM_SETTINGS_RUNTIME"] = runtime
    return runtime


def publish_controller_settings(config):
    """Only the scheduler owner publishes the backend used by admin tools."""
    runtime = config.get("PLUM_SETTINGS_RUNTIME")
    if runtime is not None:
        with runtime.store.locked():
            runtime.store.write("applied.json", {"snapshot": runtime.snapshot_name})


def child_settings_environment(config):
    """Pass only snapshot identifiers, never credentials, to child processes."""
    runtime = config.get("PLUM_SETTINGS_RUNTIME")
    if runtime is None:
        return {}
    return {
        "PLUM_SETTINGS_DIR": str(runtime.store.directory),
        "PLUM_SETTINGS_SNAPSHOT": runtime.snapshot_name,
    }


def pin_controller_for_worker():
    """A manually launched worker also follows the applied controller revision."""
    if os.environ.get("PLUM_SETTINGS_SNAPSHOT"):
        return
    store = SettingsStore()
    with store.locked():
        pointer = store.read("applied.json", missing={})
        if pointer:
            if not isinstance(pointer, dict):
                raise SettingsError("Invalid applied configuration pointer.")
            name = pointer.get("snapshot")
            store.snapshot(name)
            os.environ.update(
                PLUM_SETTINGS_DIR=str(store.directory), PLUM_SETTINGS_SNAPSHOT=name
            )
        elif store.desired()["overrides"]:
            raise SettingsError(
                "Settings are pending. Start the controller before launching an indexing worker."
            )


def tool_configuration(module):
    """Administrative tools use the last booted controller, not pending edits."""
    values = {key: getattr(module, key) for key in dir(module) if key.isupper()}
    store = SettingsStore()
    with store.locked():
        pointer = store.read("applied.json", missing={})
        if pointer:
            if not isinstance(pointer, dict):
                raise SettingsError("Invalid applied configuration pointer.")
            snapshot = store.snapshot(pointer.get("snapshot"))
            for key in SETTINGS:
                values.pop(key, None)
            values.update(snapshot["values"])
        elif store.desired()["overrides"]:
            raise SettingsError(
                "Settings are pending. Start the controller before running administration tools."
            )
    return values
