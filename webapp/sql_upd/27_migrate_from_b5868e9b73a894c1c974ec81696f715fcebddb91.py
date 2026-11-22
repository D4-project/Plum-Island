"""Store the last tool inventory reported by an agent."""

# pylint: disable=invalid-name


def migrate(connection):
    """Existing agents report Nmap implicitly until their next startup."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(bots)")}
    if "has_nmap" not in columns:
        connection.execute(
            "ALTER TABLE bots ADD COLUMN has_nmap BOOLEAN NOT NULL DEFAULT 1"
        )
    if "has_masscan" not in columns:
        connection.execute(
            "ALTER TABLE bots ADD COLUMN has_masscan BOOLEAN NOT NULL DEFAULT 0"
        )
