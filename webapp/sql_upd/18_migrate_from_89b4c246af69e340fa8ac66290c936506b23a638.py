"""Add Kong gateway HTTP headers to the collected header list."""

# pylint: disable=invalid-name,duplicate-code

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"

KONG_HEADERS = (
    "x-kong-proxy-latency",
    "x-kong-upstream-latency",
    "x-kong-response-latency",
    "x-kong-admin-latency",
    "x-kong-upstream-status",
    "x-kong-request-id",
    "x-kong-total-latency",
    "x-kong-third-party-latency",
    "x-kong-client-latency",
)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("PRAGMA foreign_keys=ON")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS collected_headers (
        id INTEGER NOT NULL PRIMARY KEY,
        header_name VARCHAR(128) NOT NULL UNIQUE,
        collect_value BOOLEAN NOT NULL DEFAULT 0
    )
    """)

cursor.executemany(
    "INSERT OR IGNORE INTO collected_headers (header_name, collect_value) VALUES (?, 0)",
    [(header_name,) for header_name in KONG_HEADERS],
)

conn.commit()
conn.close()

print("Kong HTTP headers collection migration complete")
