"""Store filtered scan profiles, preparation state and generated targets."""

# pylint: disable=invalid-name


def migrate(connection):
    """Add resumable filtered scan state without changing existing profiles."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(scanprofiles)")}
    if "search_query" not in columns:
        connection.execute("ALTER TABLE scanprofiles ADD COLUMN search_query TEXT")
    if "filter_enabled" not in columns:
        connection.execute(
            "ALTER TABLE scanprofiles ADD COLUMN filter_enabled BOOLEAN NOT NULL DEFAULT 1"
        )
    if "filter_revision" not in columns:
        connection.execute(
            "ALTER TABLE scanprofiles ADD COLUMN filter_revision INTEGER NOT NULL DEFAULT 0"
        )

    cycle_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(scanprofile_cycles)")
    }
    for name, declaration in (
        ("filter_revision", "INTEGER"),
        ("preparation_status", "VARCHAR(32)"),
        ("filter_query", "TEXT"),
        ("filter_from_ts", "BIGINT"),
        ("filter_to_ts", "BIGINT"),
    ):
        if name not in cycle_columns:
            connection.execute(
                f"ALTER TABLE scanprofile_cycles ADD COLUMN {name} {declaration}"
            )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS filtered_scan_targets (
            id INTEGER PRIMARY KEY,
            cycle_id INTEGER NOT NULL REFERENCES scanprofile_cycles(id),
            configured_target_id INTEGER NOT NULL REFERENCES targets(id),
            target_kind VARCHAR(8) NOT NULL,
            target_value VARCHAR(253) NOT NULL,
            ports TEXT NOT NULL,
            completed_ports TEXT,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            job_id INTEGER REFERENCES jobs(id),
            CONSTRAINT uq_filtered_cycle_target
                UNIQUE (cycle_id, target_kind, target_value)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_filtered_cycle_status_ports
        ON filtered_scan_targets (cycle_id, status, ports)
    """)
    work_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(filtered_scan_targets)")
    }
    if "completed_ports" not in work_columns:
        connection.execute(
            "ALTER TABLE filtered_scan_targets ADD COLUMN completed_ports TEXT"
        )
