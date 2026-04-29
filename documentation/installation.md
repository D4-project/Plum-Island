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
git clone https://github.com/D4-project/Plum-Island
cd Plum-Island
./setup.sh
```

It will ask for location of KVRocks and MeilliSearch
```
-------------------------
Basic Configuration:
KVROCKS Host Instance : 127.0.0.1
KVROCKS Port : 6666
Meili Database Host Instance : 127.0.0.1
Meili Database Port : 7700
Meili Database Password : YouNeedToChangeMeInProduction
Enable CIRCL Passive DNS enrichment ? (y/n) : y
CIRCL Passive DNS username : you@example.org
CIRCL Passive DNS API key/password :
-------------------------
KvRocsk Configuration : 127.0.0.1:6666
Meili Configuration : http://127.0.0.1:7700 using YouNeedToChangeMeInProduction
CIRCL Passive DNS : enabled for you@example.org
You may change all this configuration later in config.py
-------------------------
Are the parameters correct ? (y/n) :
```

If Passive DNS is enabled, the setup script writes `PASSIVE_USER` and `PASSIVE_PWD` in `webapp/config.py`.
Leave it disabled if you do not have CIRCL Passive DNS credentials; the IP detail page and reports will skip this enrichment.

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
