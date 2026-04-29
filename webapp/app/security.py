"""
This module implemenets additional item in the security menu.
"""

from flask_appbuilder.security.sqla.manager import SecurityManager


class CustomSecurityManager(SecurityManager):
    """
    Class to implement shortcut in security folder
    """

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
