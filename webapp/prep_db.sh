#!/usr/bin/env bash
set -euo pipefail

database_path="app.db"

# Check that the database exists
if [[ ! -f "$database_path" ]]; then
    echo "Error: database not found: $database_path" >&2
    exit 1
fi

# Check if the database is currently used by another process
if command -v lsof >/dev/null 2>&1; then
    if lsof "$database_path" >/dev/null 2>&1; then
        echo "Error: database is currently open by another process." >&2
        lsof "$database_path"
        exit 1
    fi
fi

# Flush WAL content into the main database and truncate WAL
sqlite3 "$database_path" <<'SQL'
PRAGMA wal_checkpoint(TRUNCATE);
PRAGMA journal_mode=DELETE;
VACUUM;
SQL

# Remove leftover SQLite WAL/shared-memory files if present
rm -f "${database_path}-shm" "${database_path}-wal"

echo "Database flushed successfully: $database_path"
