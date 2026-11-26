"""Add Masscan address-family capabilities and family-scoped jobs."""


def migrate(connection):
    """Extend bot inventory and persist a family for Masscan work items."""
    for table, columns in {
        "bots": (
            ("masscan_ip_v4", "VARCHAR(45)"),
            ("masscan_ip_v6", "VARCHAR(45)"),
            ("masscan_ipv4", "BOOLEAN NOT NULL DEFAULT 0"),
            ("masscan_ipv6", "BOOLEAN NOT NULL DEFAULT 0"),
        ),
        "jobs": (("scan_family", "VARCHAR(4)"),),
    }.items():
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns:
            if name not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    # The same requested FQDN can have independent IPv4 and IPv6 work.
    work_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(filtered_scan_targets)")
    }
    if "scan_family" not in work_columns:
        connection.execute(
            "ALTER TABLE filtered_scan_targets ADD COLUMN scan_family VARCHAR(4)"
        )
    connection.execute("""
        CREATE TABLE filtered_scan_targets_new (
            id INTEGER PRIMARY KEY,
            cycle_id INTEGER NOT NULL REFERENCES scanprofile_cycles(id),
            configured_target_id INTEGER NOT NULL REFERENCES targets(id),
            target_kind VARCHAR(8) NOT NULL,
            target_value VARCHAR(253) NOT NULL,
            scan_family VARCHAR(4),
            ports TEXT NOT NULL,
            completed_ports TEXT,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            job_id INTEGER REFERENCES jobs(id),
            CONSTRAINT uq_filtered_cycle_target_family
                UNIQUE (cycle_id, target_kind, target_value, scan_family)
        )
    """)
    connection.execute("""
        INSERT INTO filtered_scan_targets_new
            (id, cycle_id, configured_target_id, target_kind, target_value,
             scan_family, ports, completed_ports, status, job_id)
        SELECT id, cycle_id, configured_target_id, target_kind, target_value,
               scan_family, ports, completed_ports, status, job_id
          FROM filtered_scan_targets
    """)
    connection.execute("DROP TABLE filtered_scan_targets")
    connection.execute(
        "ALTER TABLE filtered_scan_targets_new RENAME TO filtered_scan_targets"
    )
    connection.execute("""
        CREATE INDEX idx_filtered_cycle_status_ports
        ON filtered_scan_targets (cycle_id, status, ports)
    """)

    profile_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(scanprofiles)")
    }
    if "priority_retag_pending" in profile_columns:
        connection.execute("""
            UPDATE scanprofiles
               SET priority_retag_pending = 1
             WHERE id IN (
                   SELECT DISTINCT scanprofile_id
                     FROM jobs
                    WHERE scan_tool = 'masscan'
                      AND scan_family IS NULL
                      AND finished = 0
             )
        """)
