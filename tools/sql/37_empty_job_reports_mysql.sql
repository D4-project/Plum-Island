-- Apply once to the existing Plum MySQL database before deploying the new code.
ALTER TABLE jobs ADD COLUMN report_empty BOOLEAN NOT NULL DEFAULT 0;
