# Supported release: v0.2604.0
# Build this image from a checkout of tag v0.2604.0.
# The main branch requires additional import steps (tag rules, header
# collection) that are not yet integrated into the Docker setup.
FROM python:3.13-slim

LABEL org.opencontainers.image.version="0.2604.0" \
      org.opencontainers.image.source="https://github.com/D4-project/Plum-Island" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /plum

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY webapp/ ./webapp/
COPY tools/ ./tools/
COPY nse/ ./nse/

RUN mkdir -p /plum/webapp/app/jsons /plum/webapp/app/export_jobs /plum/data

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /plum/webapp
EXPOSE 5000

ENTRYPOINT ["docker-entrypoint.sh"]
