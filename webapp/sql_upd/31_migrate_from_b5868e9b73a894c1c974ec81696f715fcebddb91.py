"""Store the dedicated Masscan source address announced at agent startup."""

# pylint: disable=invalid-name


def migrate(connection):
    """Apply this schema change without committing the caller transaction."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(bots)")}
    if "masscan_ip" not in columns:
        connection.execute("ALTER TABLE bots ADD COLUMN masscan_ip VARCHAR(45)")
