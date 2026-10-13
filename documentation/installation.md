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
git clone --recurse-submodules https://github.com/D4-project/Plum-Island
cd Plum-Island
./setup.sh
```

The tag rules are provided by the `Plum-Antibodies` submodule. `setup.sh`
synchronizes and initializes it automatically.

To refresh an existing clone, run this from the Plum-Island root:

```bash
./updisland.sh
```

This fast-forwards Plum-Island `main`, initializes submodules, then fetches the
remote tip of Plum-Antibodies (not just the pinned revision). It finally runs
`.venv/bin/python tools/initial_setup.py --roles-only`, modifying configured SQL
role permissions. Preserve local changes first and keep the existing virtualenv
available. This does not import tag YAML into SQL, reindex tags, install new
dependencies or apply numbered migrations. Follow the version-specific upgrade
guide when those steps are needed. For a reproducible release deployment, use
the selected application revision and its pinned submodule, not this remote-tip
update convenience script.

On a fresh install, `setup.sh` (not `updisland.sh`) asks for backend settings:

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
Kvrocks Configuration : 127.0.0.1:6666
Meili Configuration : http://127.0.0.1:7700 using YouNeedToChangeMeInProduction
CIRCL Passive DNS : enabled for you@example.org
You may change all this configuration later in config.py
-------------------------
Are the parameters correct ? (y/n) :
```

If Passive DNS is enabled, the setup script writes `PASSIVE_USER` and `PASSIVE_PWD` in `webapp/config.py`.
Leave it disabled if you do not have CIRCL Passive DNS credentials; the IP detail page and reports will skip this enrichment.

Review `webapp/config.py` and adapt it to your environment.

For upgrades to `v0.2610.0`, choose the [migration guide matching your installed version](migration.md): separate procedures cover `v0.2604.0` and `v0.2606.0`. Do not run a fresh setup against production data in place of a migration.

For a local demo run:

```bash
source .venv/bin/activate
cd webapp
python run.py
```

### Application logs

Enable persistent direct-run logs in `webapp/config.py`:

```python
LOG_ENABLED = True
LOG_LEVEL = "INFO"
LOG_DIR = "./log"
LOG_ROTATION_DAYS = 1
LOG_RETENTION_DAYS = 90
```

The application creates the directory and writes date-named files such as
`./log/agent-260722.log`. It switches files at local midnight even when the
application remains running. Generated logs are ignored by Git and removed
after the configured retention period.

## Docker

### Requirements

- Docker Engine 24+
- Docker Compose v2

Use a clean recursive checkout as the build context. The image installs the local
`webapp/tags` Python package from `requirements.txt`, so that submodule must be
initialized before building. Keep production configuration, credentials and scan
data outside the build context; do not build an image from a live data checkout.
The shipped launcher is a development/demo server; see the runtime limitations
below before treating this stack as a production deployment.

### Quick start

```bash
git clone --recurse-submodules https://github.com/D4-project/Plum-Island
cd Plum-Island
cp .env.example .env
```

Edit `.env` and set at minimum:

```
MEILI_KEY=<a strong random string>
```

Create the required external network once, before the first Compose start:

```bash
docker network inspect plum_net >/dev/null 2>&1 || docker network create plum_net
```

Then start the stack:

```bash
docker compose up --build
```

On first run the entrypoint will:

1. Generate `webapp/config.py` from the environment variables
2. Create the SQLite database and admin user
3. Load initial TCP ports, HTTP header tagging, tag rules, NSE scripts, and default scan profile via `tools/initial_setup.py`
4. Create the `Feeder` API role for automated target import tools
5. Print the admin credentials to stdout — save them before they scroll away

```
[plum] =================================================
[plum]  Admin user    : admin
[plum]  Admin password: <generated>
[plum] =================================================
```

The webapp is then reachable at `http://localhost:5000`.

### Configuration

The following settings are exposed by Compose through `.env` (see
`.env.example`). This is not an environment mapping for all Flask configuration:

| Variable | Required | Description |
|---|---|---|
| `MEILI_KEY` | Yes | Meilisearch master key |
| `SECRET_KEY` | No | Flask secret key (auto-generated if unset) |
| `ADMIN_USER` | No | Admin username (default: `admin`) |
| `ADMIN_EMAIL` | No | Admin email (default: `admin@plum.local`) |
| `ADMIN_PASSWORD` | No | Admin password (auto-generated if unset) |
| `PASSIVE_USER` | No | CIRCL Passive DNS username |
| `PASSIVE_PWD` | No | CIRCL Passive DNS API key |

Compose also supplies `MEILI_DATABASE_URI`, `KVROCKS_HOST` and `KVROCKS_PORT`
using internal service names. The entrypoint generates `webapp/config.py` only
if that file is absent. Changing environment values does not rewrite an existing
config; a simple restart of the same container does not regenerate it. Config
is otherwise stored in the container layer, not a named volume. Set a stable
`SECRET_KEY` for deployments that recreate containers.

### Persistent custom configuration, including report SMTP

`REPORT_SMTP_*` variables are not mapped from the environment by the current
Compose file/entrypoint. Use a complete config file mounted read-only for settings
such as SMTP. Keep it outside the repository/build context. For an existing
installation, preserve its secret key and backend settings rather than replacing
them with template defaults.

For a new installation, create a host file from the template, then edit it:

```bash
mkdir -p /srv/plum-config
cp webapp/config.py.template /srv/plum-config/config.py
chmod 600 /srv/plum-config/config.py
```

Set at least the following values in that file, replacing placeholders with your
actual secrets and relay. Keep all other required template settings:

```python
SECRET_KEY = "replace-with-a-stable-random-secret"
MEILI_KEY = "same-master-key-as-compose-env"
MEILI_DATABASE_URI = "http://plum-meilisearch:7700"
KVROCKS_HOST = "plum-kvrocks"
KVROCKS_PORT = 6666
SQLALCHEMY_DATABASE_URI = "sqlite:////plum/data/app.db"
REPORT_SMTP_HOST = "smtp.example.org"
REPORT_SMTP_PORT = 587
REPORT_SMTP_FROM = "plum@example.org"
REPORT_SMTP_USER = "plum@example.org"
REPORT_SMTP_PASSWORD = "replace-with-relay-password"
REPORT_SMTP_USE_TLS = True
REPORT_SMTP_USE_SSL = False
```

The SQLite path is essential: it keeps the database on the existing persistent
volume. The mounted file is authoritative; the entrypoint skips environment
substitution, including Passive DNS values. Set those in the file if required.
Compose still needs `.env` for the Meilisearch service and initial admin creation.

Create `docker-compose.config.yml` alongside `docker-compose.yml` with this
override (no secrets in the override itself):

```yaml
services:
  plum-webapp:
    volumes:
      - type: bind
        source: /srv/plum-config/config.py
        target: /plum/webapp/config.py
        read_only: true
        bind:
          create_host_path: false
```

Validate the merged configuration, then start/recreate the webapp with both files:

```bash
test -f /srv/plum-config/config.py
docker compose -f docker-compose.yml -f docker-compose.config.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.config.yml up -d --build
```

Check the loaded non-secret setting without importing Flask or starting a scheduler:

```bash
docker compose -f docker-compose.yml -f docker-compose.config.yml exec plum-webapp \
  python -c 'import config; print(config.REPORT_SMTP_FROM)'
```

Use both Compose files for subsequent operations. After editing the host config,
recreate the webapp with `up -d --force-recreate plum-webapp` using those same
`-f` arguments; this also refreshes the bind mount after atomic file replacement.
Do not delete named volumes. Retain the previous config for rollback and verify
this procedure on a disposable deployment first. See [Reports](reports.md#smtp-settings)
for sender fallback, relay transport and delivery verification.

### Persistence

Data is stored in named Docker volumes that survive container restarts and rebuilds:

| Volume | Contents |
|---|---|
| `plum_data` | SQLite database (`app.db`) |
| `plum_jsons` | Scan result JSON files |
| `plum_exports` | Async export jobs |
| `plum_uploads` | Uploaded NSE files and other application uploads |
| `kvrocks_data` | Kvrocks indexed data |
| `meili_data` | Meilisearch index data |

To stop the stack without losing data:

```bash
docker compose down        # stops containers, keeps volumes
```

Do not add `-v`: it deletes the named data volumes. With a custom configuration,
keep using both `-f` arguments for this command as well.

### Connecting Plum-Agent

Plum-Agent runs as a separate Docker Compose stack. Because each stack gets its own isolated bridge network by default, the agent container cannot reach the Island `plum-webapp` service by name unless they share an external network.

The quick start already creates the shared network. If it is not present yet:

```bash
docker network create plum_net
```

This is declared as an external network in Plum-Island's `docker-compose.yml`.
Only `plum-webapp` joins `plum_net`; `plum-kvrocks` and `plum-meilisearch` do not.
Both backend services nevertheless publish host ports in the default Compose
file; external-network membership does not imply host-port isolation.

**In the Plum-Agent stack**, set the Island URL to the `plum-webapp` service name:

```bash
PLUM_ISLAND=http://plum-webapp:5000
```

Start both stacks (order does not matter):

```bash
# Plum-Island directory
docker compose up -d

# Plum-Agent directory
docker compose up -d
```

See the [Plum-Agent repository](https://github.com/D4-project/Plum-Agent) for agent installation and configuration.

## Runtime services

Plum Island expects:

- Kvrocks for indexed search structures
- Meilisearch for full scan result documents
- scanner agents able to fetch jobs from the web application

Application metadata is stored in a local SQLite database file managed by the web application setup/runtime. It does not require a separate database service installation.

### Scheduler startup and production limitations

The tracked `webapp/run.py` starts Flask's development server on port 5000 with
`debug=True`. The Docker entrypoint runs that same file. These are demo launchers,
not a production-safe WSGI/scheduler deployment recipe.

`webapp/app/__init__.py` imports the scheduler only when
`WERKZEUG_RUN_MAIN == "true"`, which normally identifies the development reloader's
child process. Importing `app` in an ordinary WSGI worker does not start scheduling.
Importing `app.scheduler` has side effects: it initializes backends and starts
APScheduler immediately. There is no shipped standalone scheduler launcher or
cross-process leader election. `max_instances=1` is per scheduler, not a lock
across web workers.

Do not enable the debugger in production or set `WERKZEUG_RUN_MAIN=true` on every
WSGI worker to work around this. A production deployment needs an explicit,
supervised single scheduler owner and web workers that do not start their own
schedulers. Implementing/testing that launcher and its shutdown lifecycle is
separate deployment work; this guide does not claim it is already provided.

On a controlled demo/test instance, verify startup and execution separately:

- one process logs scheduler startup and owns the interval jobs
  `network_enrichment`, `scan_orchestration` and `scheduler_maintenance`;
- after `SCHEDULER_DELAY` minutes, task logs show completed orchestration and
  maintenance ticks (including errors if a backend is unavailable);
- creating multiple web workers must not create multiple scheduler owners;
- stop/restart checks must not leave a second owner running.

Seeing the web UI or a `Scheduler Imported` log alone does not prove recurring
work executes. Verify process ownership and later task logs before enabling
agents or scheduled reports. No production-safe launcher is added by the
documentation correction.
