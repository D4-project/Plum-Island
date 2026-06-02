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
CIRCL Passive DNS API key/password : YouNeedToChangeItToo
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

## Docker (v0.2604.0)

> **Supported release: v0.2604.0**
> The `main` branch requires additional import steps not yet integrated into the Docker setup. Always build from the `v0.2604.0` tag.

### Requirements

- Docker Engine 24+
- Docker Compose v2

### Quick start

```bash
git clone https://github.com/D4-project/Plum-Island
cd Plum-Island
git checkout v0.2604.0
cp .env.example .env
```

Edit `.env` and set at minimum:

```
MEILI_KEY=<a strong random string>
```

Then start the stack:

```bash
docker compose up --build
```

On first run the entrypoint will:
1. Generate `webapp/config.py` from the environment variables
2. Create the SQLite database and admin user
3. Load initial TCP ports, HTTP header tagging, tag rules, NSE scripts, and default scan profile via `tools/initial_setup.py`
4. Print the admin credentials to stdout — save them before they scroll away

```
[plum] =================================================
[plum]  Admin user    : admin
[plum]  Admin password: <generated>
[plum] =================================================
```

The webapp is then reachable at `http://localhost:5000`.

### Configuration

All settings are passed as environment variables (see `.env.example`):

| Variable | Required | Description |
|---|---|---|
| `MEILI_KEY` | Yes | Meilisearch master key |
| `SECRET_KEY` | No | Flask secret key (auto-generated if unset) |
| `ADMIN_USER` | No | Admin username (default: `admin`) |
| `ADMIN_EMAIL` | No | Admin email (default: `admin@plum.local`) |
| `ADMIN_PASSWORD` | No | Admin password (auto-generated if unset) |
| `PASSIVE_USER` | No | CIRCL Passive DNS username |
| `PASSIVE_PWD` | No | CIRCL Passive DNS API key |

### Persistence

Data is stored in named Docker volumes that survive container restarts and rebuilds:

| Volume | Contents |
|---|---|
| `plum_data` | SQLite database (`app.db`) |
| `plum_jsons` | Scan result JSON files |
| `plum_exports` | Async export jobs |
| `kvrocks_data` | Kvrocks indexed data |
| `meili_data` | Meilisearch index data |

To stop the stack without losing data:

```bash
docker compose down        # stops containers, keeps volumes
docker compose down -v     # stops containers AND deletes all volumes
```

## Runtime services

Plum Island expects:

- Kvrocks for indexed search structures
- Meilisearch for full scan result documents
- scanner agents able to fetch jobs from the web application

Application metadata is stored in a local SQLite database file managed by the web application setup/runtime. It does not require a separate database service installation.

Production deployments should run the Flask application behind a proper web server and supervise the scheduler/processes according to the local operating model.
