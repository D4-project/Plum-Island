"""Store bounded ingestion queue history and accepted per-job document counts."""

# pylint: disable=invalid-name


def migrate(connection):
    """Preserve existing jobs and leave their unmeasured counts unknown."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    if "report_document_count" not in columns:
        connection.execute("ALTER TABLE jobs ADD COLUMN report_document_count BIGINT")
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_jobs_ingestion_queue
        ON jobs (active, exported, finished, meili_documents_total, report_document_count)
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS ingestion_stat_samples (
            sampled_at DATETIME NOT NULL PRIMARY KEY,
            pending_reports BIGINT NOT NULL,
            pending_documents BIGINT NOT NULL,
            unknown_reports BIGINT NOT NULL
        )
    """)
