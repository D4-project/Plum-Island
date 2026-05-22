"""
Add curated HTTP header collection configuration.
This sql update script import in the table a selection of header

some header name are only collected : collected_headers
for some header the value matter : value_collected_headers

"""

# pylint: disable=invalid-name

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"

COLLECTED_HEADERS = [
    "cache-control",
    "clear-site-data",
    "content-type",
    "content-security-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-dns-prefetch-control",
    "x-frame-options",
    "x-permitted-cross-domain-policies",
    "$wsep",
    "host-header",
    "k-proxy-request",
    "liferay-portal",
    "oraclecommercecloud-version",
    "pega-host",
    "powered-by",
    "product",
    "sourcemap",
    "www-authenticate",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-atmosphere-error",
    "x-atmosphere-first-request",
    "x-atmosphere-tracking-id",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-spanid",
    "x-b3-traceid",
    "x-beserver",
    "x-backside-transport",
    "x-cf-powered-by",
    "x-cms",
    "x-calculatedbetarget",
    "x-cocoon-version",
    "x-content-encoded-by",
    "x-diaginfo",
    "x-envoy-attempt-count",
    "x-envoy-external-address",
    "x-envoy-internal",
    "x-envoy-original-dst-host",
    "x-envoy-upstream-service-time",
    "x-feserver",
    "x-framework",
    "x-generated-by",
    "x-generator",
    "x-gitlab-meta",
    "x-jitsi-release",
    "x-joomla-version",
    "x-kubernetes-pf-flowschema-ui",
    "x-kubernetes-pf-prioritylevel-uid",
    "x-litespeed-cache",
    "x-litespeed-purge",
    "x-litespeed-tag",
    "x-litespeed-vary",
    "x-litespeed-cache-control",
    "x-mod-pagespeed",
    "x-nextjs-cache",
    "x-nextjs-matched-path",
    "x-nextjs-page",
    "x-nextjs-redirect",
    "x-owa-version",
    "x-old-content-length",
    "x-oneagent-js-injection",
    "x-page-speed",
    "x-php-version",
    "x-powered-by",
    "x-powered-by-plesk",
    "x-powered-cms",
    "x-redirect-by",
    "x-server-powered-by",
    "x-sourcefiles",
    "x-sourcemap",
    "x-turbo-charged-by",
    "x-umbraco-version",
    "x-varnish-backend",
    "x-varnish-server",
    "x-woodpecker-version",
    "x-dtagentid",
    "x-dthealthcheck",
    "x-dtinjectedservlet",
    "x-ruxit-js-agent",
]

VALUE_COLLECTED_HEADERS = {
    "x-powered-by",
    "x-server-powered-by",
    "powered-by",
    "product",
    "x-generator",
    "x-generated-by",
    "x-powered-cms",
    "x-varnish-backend",
    "x-varnish-server",
    "x-cms",
    "x-framework",
    "x-redirect-by",
    "x-turbo-charged-by",
    "liferay-portal",
    "x-content-encoded-by",
    "x-cf-powered-by",
    "x-owa-version",
    "x-cocoon-version",
    "x-jitsi-release",
    "oraclecommercecloud-version",
    "x-woodpecker-version",
    "x-joomla-version",
    "x-umbraco-version",
    "x-php-version",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "content-type",
    "www-authenticate",
}

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
    "INSERT OR IGNORE INTO collected_headers (header_name, collect_value) VALUES (?, ?)",
    [
        (header_name, 1 if header_name in VALUE_COLLECTED_HEADERS else 0)
        for header_name in COLLECTED_HEADERS
    ],
)

cursor.executemany(
    "UPDATE collected_headers SET collect_value = 1 WHERE header_name = ?",
    [(header_name,) for header_name in VALUE_COLLECTED_HEADERS],
)

conn.commit()
conn.close()

print("HTTP headers to collect migration complete")
