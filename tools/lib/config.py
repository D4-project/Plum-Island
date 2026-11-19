"""Configuration helpers shared by tools."""

from pathlib import Path

import yaml


def load_yaml_config(config_path: str | Path) -> dict:
    """Load a YAML configuration file and return an empty dict for empty files."""
    path = Path(config_path)
    with path.open("r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def require_config_values(config: dict, keys: tuple[str, ...], config_path: str | Path):
    """Return required config values in key order or raise with all missing keys."""
    missing = [key for key in keys if not config.get(key)]
    if missing:
        raise KeyError(f"Missing {', '.join(missing)} in {config_path}")

    return tuple(config[key] for key in keys)


def plum_credentials_from_config(config: dict, config_path: str | Path):
    """Return Plum API base URL, username, and password from a config mapping."""
    return require_config_values(
        config,
        ("PLUMISLAND", "PLUMAPIUSER", "PLUMAPIPWD"),
        config_path,
    )
