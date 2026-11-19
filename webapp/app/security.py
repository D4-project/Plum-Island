"""
This module implemenets additional item in the security menu.
"""

from flask_appbuilder.security.sqla.manager import SecurityManager
from sqlalchemy.exc import SQLAlchemyError
from flask_login import current_user


class CustomSecurityManager(SecurityManager):
    """
    Class to implement shortcut in security folder
    """

    def is_plum_settings_admin(self):
        """Only active members of the configured administrator role may configure Plum."""
        return bool(
            current_user.is_authenticated
            and current_user.is_active
            and any(role.name == self.auth_role_admin for role in current_user.roles)
        )

    def has_access(self, permission_name, view_name):
        """A mistaken FAB grant cannot expose application configuration."""
        if (
            view_name in {"PlumSettingsView", "Plum Settings"}
            and not self.is_plum_settings_admin()
        ):
            return False
        return super().has_access(permission_name, view_name)

    def get_user_menu_access(self, menu_names=None):
        """Hide settings consistently in both framework menus and Plum navigation."""
        menus = super().get_user_menu_access(menu_names)
        if not self.is_plum_settings_admin():
            menus = menus - {"Plum Settings"}
        return menus

    def add_permissions_view(self, base_permissions, view_menu):
        """Remove obsolete permission-view pairs atomically before FAB sync.

        FAB 4.8.1 passes a Permission rather than a PermissionView when detaching
        obsolete permissions from roles. Its deletion guard then refuses to
        remove the still-associated pair. Use the registered view's permissions
        as the authority, retaining shared Permission and ViewMenu records.
        """
        base_permissions = tuple(base_permissions)
        session = self.get_session
        try:
            view = self.find_view_menu(view_menu)
            obsolete = (
                [
                    pair
                    for pair in self.find_permissions_view_menu(view)
                    if pair.permission is not None
                    and pair.permission.name not in base_permissions
                ]
                if view is not None
                else []
            )
            for pair in obsolete:
                for role in list(pair.role):
                    role.permissions.remove(pair)
                session.delete(pair)
            if obsolete:
                session.commit()
        except SQLAlchemyError as error:
            session.rollback()
            raise RuntimeError(
                f"Failed to clean obsolete permissions for view {view_menu}"
            ) from error

        return super().add_permissions_view(base_permissions, view_menu)

    def load_user(self, pk):
        """
        Load a Flask-Login user from the session and fail closed on stale ids.

        Some Flask-AppBuilder versions assume get_user_by_id() always returns a
        user. In production, stale browser sessions can reference deleted users,
        which otherwise raises AttributeError before the user can be redirected
        to login.
        """
        try:
            user = self.get_user_by_id(int(pk))
        except (TypeError, ValueError):
            return None

        if user is None:
            return None
        if not getattr(user, "is_active", False):
            return None
        return user

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.add_custom_menu_item()

    def add_custom_menu_item(self):
        """
        Add Apikey to menu
        """
        self.appbuilder.menu.add_link(
            "Agent Keys",  # Nom de l’item
            href="/apikeysview/list/",
            category="Security",
            icon="fa-robot",
        )
