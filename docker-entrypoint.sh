#!/bin/bash
set -e

CONFIG_FILE="config.py"
DB_PATH="/plum/data/app.db"

# Generate config.py from environment on first run
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[plum] Generating config.py from environment..."
    cp config.py.template "$CONFIG_FILE"

    : "${MEILI_KEY:?MEILI_KEY environment variable is required}"
    _SECRET="${SECRET_KEY:-$(head -c32 /dev/urandom | base64)}"
    _MEILI_URI="${MEILI_DATABASE_URI:-http://meilisearch:7700}"
    _KVROCKS_HOST="${KVROCKS_HOST:-kvrocks}"
    _KVROCKS_PORT="${KVROCKS_PORT:-6666}"

    sed -i "s|^SECRET_KEY *=.*|SECRET_KEY = \"${_SECRET}\"|" "$CONFIG_FILE"
    sed -i "s|^MEILI_KEY *=.*|MEILI_KEY = \"${MEILI_KEY}\"|" "$CONFIG_FILE"
    sed -i "s|^MEILI_DATABASE_URI *=.*|MEILI_DATABASE_URI = \"${_MEILI_URI}\"|" "$CONFIG_FILE"
    sed -i "s|^KVROCKS_HOST *=.*|KVROCKS_HOST = \"${_KVROCKS_HOST}\"|" "$CONFIG_FILE"
    sed -i "s|^KVROCKS_PORT *=.*|KVROCKS_PORT = ${_KVROCKS_PORT}|" "$CONFIG_FILE"
    # Point SQLite at the persistent data volume
    sed -i "s|^SQLALCHEMY_DATABASE_URI *=.*sqlite.*|SQLALCHEMY_DATABASE_URI = \"sqlite:///${DB_PATH}\"|" "$CONFIG_FILE"

    if [ -n "${PASSIVE_USER:-}" ]; then
        sed -i "s|^PASSIVE_USER *=.*|PASSIVE_USER = \"${PASSIVE_USER}\"|" "$CONFIG_FILE"
        sed -i "s|^PASSIVE_PWD *=.*|PASSIVE_PWD = \"${PASSIVE_PWD:-}\"|" "$CONFIG_FILE"
    fi
fi

# First-run database initialization
if [ ! -f "$DB_PATH" ]; then
    echo "[plum] First run: initializing database..."
    _ADMIN_PWD="${ADMIN_PASSWORD:-$(head -c16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c16)}"
    flask fab create-admin \
        --username "${ADMIN_USER:-admin}" \
        --firstname Admin --lastname Admin \
        --email "${ADMIN_EMAIL:-admin@plum.local}" \
        --password "$_ADMIN_PWD"
    echo "[plum] ================================================="
    echo "[plum]  Admin user    : ${ADMIN_USER:-admin}"
    echo "[plum]  Admin password: $_ADMIN_PWD"
    echo "[plum] ================================================="

    echo "[plum] Loading initial TCP ports, tag rules and NSE scripts..."
    python ../tools/initial_setup.py
fi

exec python run.py
