"""Retire SQLite-backed filtered scan preparation at the Kvrocks cutover."""

# pylint: disable=invalid-name


def migrate(connection):
    """Close old filtered cycles while preserving jobs already held by agents."""
    cycle_ids = [row[0] for row in connection.execute("""
            SELECT id
              FROM scanprofile_cycles
             WHERE status = 'running'
               AND filter_revision IS NOT NULL
            """)]
    if not cycle_ids:
        return
    placeholders = ",".join("?" for _cycle_id in cycle_ids)
    connection.execute(
        f"""
        UPDATE jobs
           SET finished = 1,
               exported = 1,
               job_end = CURRENT_TIMESTAMP
         WHERE scanprofile_cycle_id IN ({placeholders})
           AND active = 0
           AND finished = 0
        """,
        cycle_ids,
    )
    connection.execute(
        f"DELETE FROM filtered_scan_targets WHERE cycle_id IN ({placeholders})",
        cycle_ids,
    )
    connection.execute(
        f"""
        UPDATE scanprofile_cycles
           SET status = 'finished',
               finished_at = CURRENT_TIMESTAMP,
               preparation_status = 'legacy_sql_superseded'
         WHERE id IN ({placeholders})
        """,
        cycle_ids,
    )
    connection.execute(
        f"""
        UPDATE scanprofiles
           SET current_cycle_id = NULL,
               last_cycle_finished_at = CURRENT_TIMESTAMP
         WHERE current_cycle_id IN ({placeholders})
        """,
        cycle_ids,
    )
