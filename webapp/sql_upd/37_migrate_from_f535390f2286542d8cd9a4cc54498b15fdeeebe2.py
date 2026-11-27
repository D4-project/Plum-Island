"""Mark jobs whose accepted empty report has no file on disk."""

# pylint: disable=invalid-name


def migrate(connection):
    """Add the marker without changing how existing reports are retrieved."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    if "report_empty" not in columns:
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN report_empty BOOLEAN NOT NULL DEFAULT 0"
        )
