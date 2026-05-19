FROM python:3.13-slim

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
