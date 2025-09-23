"""
This module implemenets additional item in the security menu.
"""

from flask_appbuilder.security.sqla.manager import SecurityManager


class CustomSecurityManager(SecurityManager):
    """
    Class to implement shortcut in security folder
    """

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
            icon="fa-folder-open-o",
        )
