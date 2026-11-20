"""Merge duplicate protocol/port definitions and preserve their scan profiles."""

# pylint: disable=invalid-name


def merge_duplicates(connection):
    """Replace all links in duplicate groups with their distinct surviving links."""
    connection.execute(
        "CREATE TEMP TABLE port_merge (old_id INTEGER PRIMARY KEY, keep_id INTEGER NOT NULL)"
    )
    connection.execute("""
        INSERT INTO port_merge
        SELECT p.id, duplicates.keep_id
        FROM ports AS p JOIN (
            SELECT proto_id, value, MIN(id) AS keep_id
            FROM ports GROUP BY proto_id, value HAVING COUNT(*) > 1
        ) AS duplicates USING (proto_id, value)
    """)
    for old, kept, old_name, kept_name in connection.execute("""
        SELECT p.id, k.id, p.name, k.name FROM port_merge AS m
        JOIN ports AS p ON p.id = m.old_id JOIN ports AS k ON k.id = m.keep_id
        WHERE p.id != k.id ORDER BY k.id, p.id
    """):
        details = (
            f" (description {old_name!a}, keeping {kept_name!a})"
            if old_name != kept_name
            else ""
        )
        print(f"Merging port ID {old} into {kept}{details}")
    connection.execute("""
        CREATE TEMP TABLE merged_port_links AS
        SELECT DISTINCT a.scanprofile_id, m.keep_id AS port_id
        FROM scanprofiles_ports_assoc AS a JOIN port_merge AS m ON a.port_id = m.old_id
    """)
    connection.execute(
        "DELETE FROM scanprofiles_ports_assoc WHERE port_id IN (SELECT old_id FROM port_merge)"
    )
    connection.execute("""
        INSERT INTO scanprofiles_ports_assoc (scanprofile_id, port_id)
        SELECT scanprofile_id, port_id FROM merged_port_links
    """)
    connection.execute(
        "DELETE FROM ports WHERE id IN (SELECT old_id FROM port_merge WHERE old_id != keep_id)"
    )
    connection.execute("DROP TABLE temp.merged_port_links")
    connection.execute("DROP TABLE temp.port_merge")


def normalize_legacy_keys(connection):
    """Free stale keys before assigning canonical keys, including swapped pairs."""
    prefix = "~"
    while connection.execute(
        "SELECT 1 FROM ports WHERE proto_to_port GLOB ? LIMIT 1", (prefix + "*",)
    ).fetchone():
        prefix += "~"
    connection.execute(
        """
        UPDATE ports SET proto_to_port = ? || id
        WHERE proto_to_port != (value || ':' || proto_id)
    """,
        (prefix,),
    )
    connection.execute(
        """
        UPDATE ports SET proto_to_port = value || ':' || proto_id
        WHERE proto_to_port GLOB ?
    """,
        (prefix + "*",),
    )


def migrate(connection):
    """Run under the updater's write transaction for fresh and existing schemas."""
    merge_duplicates(connection)
    normalize_legacy_keys(connection)
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_ports_proto_value ON ports(proto_id, value)"
    )
    indexes = connection.execute("PRAGMA index_list(ports)")
    columns = connection.execute("PRAGMA index_info(uq_ports_proto_value)")
    if not any(
        row[1] == "uq_ports_proto_value" and row[2] and not row[4] for row in indexes
    ) or [row[2] for row in columns] != ["proto_id", "value"]:
        raise ValueError("Existing uq_ports_proto_value has an incompatible definition")
