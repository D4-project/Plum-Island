#!/usr/bin/env python3
"""
Initial database content loader for Plum Island.

This imports bundled YAML tag rules, clones/updates the public NSE rule
repository, and imports NSE scripts into the application database.
"""

import argparse
import hashlib
import logging
import subprocess
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
WEBAPP_DIR = BASE_DIR / "webapp"
DEFAULT_NSE_REPO_URL = "https://github.com/D4-project/Plum-Rules-NSE"
DEFAULT_NSE_REPO_DIR = BASE_DIR / "external" / "Plum-Rules-NSE"
DEFAULT_ROLE_FILE = WEBAPP_DIR / "security_roles" / "read_only.yaml"


def parse_args():
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Load initial Plum Island tag rules and NSE scripts."
    )
    parser.add_argument(
        "--skip-tags",
        action="store_true",
        help="Do not import YAML tag rules into the database.",
    )
    parser.add_argument(
        "--skip-nse",
        action="store_true",
        help="Do not clone/import NSE scripts.",
    )
    parser.add_argument(
        "--skip-roles",
        action="store_true",
        help="Do not create/update configured security roles.",
    )
    parser.add_argument(
        "--role-file",
        default=str(DEFAULT_ROLE_FILE),
        help=f"Security role YAML file. Default: {DEFAULT_ROLE_FILE}",
    )
    parser.add_argument(
        "--nse-repo-url",
        default=DEFAULT_NSE_REPO_URL,
        help=f"NSE git repository URL. Default: {DEFAULT_NSE_REPO_URL}",
    )
    parser.add_argument(
        "--nse-repo-dir",
        default=str(DEFAULT_NSE_REPO_DIR),
        help=f"Local NSE repository directory. Default: {DEFAULT_NSE_REPO_DIR}",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned database changes without writing.",
    )
    return parser.parse_args()


def setup_runtime():
    """
    Prepare imports for Flask-backed tools.
    """
    sys.path.insert(0, str(BASE_DIR / "tools"))
    sys.path.insert(0, str(WEBAPP_DIR))
    warnings.filterwarnings("ignore", category=Warning)
    logging.disable(logging.CRITICAL)


def import_tag_rules(dry_run=False):
    """
    Import YAML tag rules using the shared import_tags logic.
    """
    from import_tags import import_rules  # pylint: disable=import-outside-toplevel

    args = SimpleNamespace(
        tags_dir=str(WEBAPP_DIR / "tags"),
        tags_file=None,
        dry_run=dry_run,
        flush_db=False,
        quiet=False,
    )
    summary = import_rules(args)
    print(
        "Tag rules: "
        f"inserted={summary['inserted']} updated={summary['updated']} "
        f"kept_db={summary['kept_db']} unchanged={summary['unchanged']} "
        f"skipped={summary['skipped']} dry_run={dry_run}"
    )


def clone_or_update_repo(repo_url, repo_dir):
    """
    Clone the NSE repository if missing, otherwise fetch the current branch.
    """
    repo_path = Path(repo_dir)
    if repo_path.exists():
        if not (repo_path / ".git").is_dir():
            raise RuntimeError(f"{repo_path} exists but is not a git repository")
        print(f"Updating NSE repository: {repo_path}")
        subprocess.run(
            ["git", "-C", str(repo_path), "pull", "--ff-only"],
            check=True,
        )
        return repo_path

    repo_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Cloning NSE repository: {repo_url} -> {repo_path}")
    subprocess.run(
        ["git", "clone", repo_url, str(repo_path)],
        check=True,
    )
    return repo_path


def iter_nse_files(repo_path):
    """
    Iterate NSE files from a cloned repository.
    """
    for path in sorted(Path(repo_path).rglob("*.nse")):
        if ".git" not in path.parts and path.is_file():
            yield path


def stored_nse_name(filename, sha256sum):
    """
    Return a deterministic stored upload filename.
    """
    return f"initial_setup__{sha256sum[:12]}__{filename}"


def import_nse_scripts(repo_path, dry_run=False):
    """
    Import .nse files from a repository into the Flask DB.
    """
    from app import app, db  # pylint: disable=import-outside-toplevel
    from app.models import Nses  # pylint: disable=import-outside-toplevel

    summary = {
        "inserted": 0,
        "updated": 0,
        "unchanged": 0,
        "duplicate_hash": 0,
        "skipped": 0,
    }

    with app.app_context():
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)

        for nse_file in iter_nse_files(repo_path):
            try:
                filename = nse_file.name
                file_bytes = nse_file.read_bytes()
                sha256sum = hashlib.sha256(file_bytes).hexdigest()
                existing_by_name = (
                    db.session.query(Nses).filter(Nses.name == filename).one_or_none()
                )
                existing_by_hash = (
                    db.session.query(Nses).filter(Nses.hash == sha256sum).one_or_none()
                )
            except Exception as error:
                summary["skipped"] += 1
                print(f"SKIP {nse_file}: {error}", file=sys.stderr)
                continue

            if existing_by_name is None and existing_by_hash is not None:
                summary["duplicate_hash"] += 1
                print(
                    f"SKIP duplicate hash {filename}: already stored as "
                    f"{existing_by_hash.name}"
                )
                continue

            item = existing_by_name
            if item is not None and item.hash == sha256sum:
                summary["unchanged"] += 1
                continue

            stored_name = stored_nse_name(filename, sha256sum)
            if item is None:
                summary["inserted"] += 1
                print(f"INSERT NSE {filename}")
                if dry_run:
                    continue
                item = Nses(name=filename, hash=sha256sum, filebody=stored_name)
                (upload_dir / stored_name).write_bytes(file_bytes)
                db.session.add(item)
                continue

            summary["updated"] += 1
            print(f"UPDATE NSE {filename}")
            if dry_run:
                continue

            old_file = upload_dir / str(item.filebody or "")
            if old_file.is_file():
                old_file.unlink()
            (upload_dir / stored_name).write_bytes(file_bytes)
            item.hash = sha256sum
            item.filebody = stored_name

        if dry_run:
            db.session.rollback()
        else:
            db.session.commit()

    print(
        "NSE scripts: "
        f"inserted={summary['inserted']} updated={summary['updated']} "
        f"unchanged={summary['unchanged']} duplicate_hash={summary['duplicate_hash']} "
        f"skipped={summary['skipped']} dry_run={dry_run}"
    )


def normalize_permission_label(label):
    """
    Convert a human-maintained FAB permission label to permission/view names.
    """
    if label.startswith("menu access on "):
        view_menu = label[len("menu access on ") :].strip()
        if not view_menu:
            raise ValueError(f"Invalid permission label: {label}")
        return "menu_access", view_menu

    if " on " not in label:
        raise ValueError(f"Invalid permission label, missing ' on ': {label}")

    permission_label, view_menu = label.rsplit(" on ", 1)
    permission_label = permission_label.strip()
    view_menu = view_menu.strip()
    if not permission_label or not view_menu:
        raise ValueError(f"Invalid permission label: {label}")

    if permission_label.startswith("can "):
        permission = "can_" + permission_label[4:].strip().replace(" ", "_")
    else:
        permission = permission_label.replace(" ", "_")

    return permission, view_menu


def load_role_definition(role_file):
    """
    Load one role definition YAML file.
    """
    path = Path(role_file)
    if not path.is_file():
        raise FileNotFoundError(f"Role file not found: {path}")

    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    role_name = str(payload.get("role") or "").strip()
    permissions = payload.get("permissions") or []
    if not role_name:
        raise ValueError(f"Missing role name in {path}")
    if not isinstance(permissions, list):
        raise ValueError(f"'permissions' must be a list in {path}")
    return role_name, [str(item).strip() for item in permissions if str(item).strip()]


def sync_security_role(role_file, dry_run=False):
    """
    Create/update one FAB role from a YAML permission list.
    """
    from app import app, appbuilder  # pylint: disable=import-outside-toplevel

    role_name, permission_labels = load_role_definition(role_file)
    with app.app_context():
        security_manager = appbuilder.sm
        permission_views = []
        for label in permission_labels:
            permission, view_menu = normalize_permission_label(label)
            permission_view = security_manager.find_permission_view_menu(
                permission,
                view_menu,
            )
            if permission_view is None:
                print(f"CREATE permission {permission} on {view_menu}")
                if dry_run:
                    continue
                permission_view = security_manager.add_permission_view_menu(
                    permission,
                    view_menu,
                )
            permission_views.append(permission_view)

        role = security_manager.find_role(role_name)
        if role is None:
            print(f"CREATE role {role_name}")
            if dry_run:
                print(
                    f"Security role {role_name}: permissions={len(permission_views)} "
                    f"dry_run={dry_run}"
                )
                return
            role = security_manager.add_role(role_name)

        print(f"SYNC role {role_name}: permissions={len(permission_views)}")
        if dry_run:
            print(
                f"Security role {role_name}: permissions={len(permission_views)} "
                f"dry_run={dry_run}"
            )
            return

        role.permissions = permission_views
        security_manager.get_session.merge(role)
        security_manager.get_session.commit()
    print(
        f"Security role {role_name}: permissions={len(permission_views)} "
        f"dry_run={dry_run}"
    )


def main():
    """
    CLI entrypoint.
    """
    args = parse_args()
    setup_runtime()

    if not args.skip_roles:
        sync_security_role(args.role_file, dry_run=args.dry_run)

    if not args.skip_tags:
        import_tag_rules(dry_run=args.dry_run)

    if not args.skip_nse:
        repo_path = clone_or_update_repo(args.nse_repo_url, args.nse_repo_dir)
        import_nse_scripts(repo_path, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
