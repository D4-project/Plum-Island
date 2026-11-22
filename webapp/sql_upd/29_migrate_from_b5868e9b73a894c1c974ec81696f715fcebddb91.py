"""Snapshot the selected scan tool on queued jobs."""

# pylint: disable=invalid-name


def migrate(connection):
    """Apply this schema change without committing the caller transaction."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    if "scan_tool" not in columns:
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN scan_tool VARCHAR(16) NOT NULL "
            "DEFAULT 'nmap' CHECK (scan_tool IN ('nmap', 'masscan'))"
        )
    if "detect_protocol" not in columns:
        connection.execute(
            "ALTER TABLE jobs ADD COLUMN detect_protocol BOOLEAN NOT NULL DEFAULT 0"
        )

    connection.execute("""
        UPDATE jobs
           SET scan_tool = COALESCE(
                   (SELECT scan_tool FROM scanprofiles WHERE scanprofiles.id = jobs.scanprofile_id),
                   'nmap'
               ),
               detect_protocol = COALESCE(
                   (SELECT detect_protocol FROM scanprofiles WHERE scanprofiles.id = jobs.scanprofile_id),
                   0
               )
         WHERE active = 0 AND finished = 0
        """)
