# Installation

## Requirements

- Python 3.10+
- Flask AppBuilder 4.8
- Meilisearch 1.22.2+
- Kvrocks unstable build 8f04af34+, with RocksDB 10.4.2+

Before starting the setup, make sure Meilisearch and Kvrocks are running and reachable from the web application.

## Setup

Clone the repository and run the setup script:

```bash
git clone <repository-url>
cd Plum-Island
./setup.sh
```

Review `webapp/config.py` and adapt it to your environment.

For a local demo run:

```bash
source .venv/bin/activate
cd webapp
python run.py
```

## Runtime services

Plum Island expects:

- Kvrocks for indexed search structures
- Meilisearch for full scan result documents
- scanner agents able to fetch jobs from the web application

Application metadata is stored in a local SQLite database file managed by the web application setup/runtime. It does not require a separate database service installation.

Production deployments should run the Flask application behind a proper web server and supervise the scheduler/processes according to the local operating model.
