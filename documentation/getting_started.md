# Getting Started

This guide walks you through your first scan end-to-end, from adding a target to reading results.

## Prerequisites

- The Plum Island stack is running and reachable at `http://localhost:5000`
- You have the admin credentials printed by the entrypoint on first start:

```
[plum] =================================================
[plum]  Admin user    : admin
[plum]  Admin password: <generated>
[plum] =================================================
```

## Step 1 — Add a target

1. Navigate to `Config > Targets`.
2. Click `+` to open the new target form.
3. Set the `CIDR / Host` field to the address range or hostname you want to scan (e.g. `192.168.1.0/24` or `example.com`).
4. Select a **Scan Profile**. The `Default banner scan` profile is available out of the box.
5. Save the record.

Plum Island automatically creates a scan job for every active `Target × ScanProfile` combination. You can verify the job was queued under `Status > Job Status`.

## Step 2 — Create an agent API key

Scans are executed by a separate Plum Agent process, not by the web application itself. The agent authenticates with an API key.

1. Navigate to `Security > Agent Keys`.
2. Click `+` to generate a new key.
3. Add a short description (e.g. `lab agent`, `docker agent`) so you can identify the key later.
4. **Copy the key immediately.** It is only shown at creation time; Plum Island stores a hashed copy afterwards.
5. Save the record.

## Step 3 — Connect a Plum Agent

Install and start a [Plum Agent](https://github.com/D4-project/Plum-Agent) using the key from Step 2.

### Native (Python)

Follow the setup instructions in the Plum Agent repository, then run:

```bash
python agent.py
```

Set the Island URL and your key in the agent configuration as documented in its README.

### Docker

If you are running Plum Island with Docker Compose, create the shared network first (one-time):

```bash
docker network create plum_net
```

Plum Island's `docker-compose.yml` already declares this as an external network; the `webapp` service joins it automatically on startup.

In the Plum Agent Compose stack, point the agent at the Island using the internal service name:

```
PLUM_ISLAND=http://plum-webapp:5000
AGENT_KEY=<key from Step 2>
```

Then start both stacks (order does not matter):

```bash
# Plum Island directory
docker compose up -d

# Plum Agent directory
docker compose up -d
```

Once the agent is running it appears in `Status > Bot Status`.

## Step 4 — View results

The agent polls for pending jobs, executes the nmap scan, and submits results back to the Island.

To follow progress and inspect results:

1. Go to `Status > Job Status` to watch the job move from queued to finished.
2. When the job completes, click the **magnifying glass** icon on that row to open the job detail view.
3. The **Show Results** panel displays the full parsed scan output.

For richer search and filtering across all collected scan data, see the [search documentation](search.md).
