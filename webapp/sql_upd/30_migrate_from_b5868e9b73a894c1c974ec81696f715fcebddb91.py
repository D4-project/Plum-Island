"""Add attempt tokens for new agents while preserving legacy dispatch."""

# pylint: disable=invalid-name


def migrate(connection):
    """Apply this schema change without committing the caller transaction."""
    bot_columns = {row[1] for row in connection.execute("PRAGMA table_info(bots)")}
    if "supports_job_attempts" not in bot_columns:
        connection.execute(
            "ALTER TABLE bots ADD COLUMN supports_job_attempts BOOLEAN NOT NULL DEFAULT 0"
        )

    job_columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    if "attempt_uid" not in job_columns:
        connection.execute("ALTER TABLE jobs ADD COLUMN attempt_uid VARCHAR(36)")
