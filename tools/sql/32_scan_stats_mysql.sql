-- Apply to the existing Plum MySQL database before deploying the new code.
CREATE TABLE IF NOT EXISTS scan_stat_buckets (
    bucket_start DATETIME NOT NULL,
    scan_tool VARCHAR(16) NOT NULL,
    jobs_completed BIGINT NOT NULL DEFAULT 0,
    ports_targeted BIGINT NOT NULL DEFAULT 0,
    open_ports BIGINT NOT NULL DEFAULT 0,
    jobs_without_target_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, scan_tool)
) ENGINE=InnoDB;
