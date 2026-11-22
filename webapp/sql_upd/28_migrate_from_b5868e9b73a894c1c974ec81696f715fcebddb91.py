"""Add tool preferences to profiles, including profiles from older installations."""

# pylint: disable=invalid-name


def migrate(connection):
    """Apply this schema change without committing the caller transaction."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(scanprofiles)")}
    if "scan_tool" not in columns:
        connection.execute(
            "ALTER TABLE scanprofiles ADD COLUMN scan_tool VARCHAR(16) NOT NULL "
            "DEFAULT 'nmap' CHECK (scan_tool IN ('nmap', 'masscan'))"
        )
    if "detect_protocol" not in columns:
        connection.execute(
            "ALTER TABLE scanprofiles ADD COLUMN detect_protocol BOOLEAN NOT NULL DEFAULT 0"
        )
