-- Apply once to the existing Plum MySQL database before deploying the new code.
ALTER TABLE jobs
    ADD COLUMN report_document_count BIGINT NULL,
    ADD INDEX idx_jobs_ingestion_queue
        (active, exported, finished, meili_documents_total, report_document_count);

CREATE TABLE IF NOT EXISTS ingestion_stat_samples (
    sampled_at DATETIME NOT NULL,
    pending_reports BIGINT NOT NULL,
    pending_documents BIGINT NOT NULL,
    unknown_reports BIGINT NOT NULL,
    PRIMARY KEY (sampled_at)
) ENGINE=InnoDB;
