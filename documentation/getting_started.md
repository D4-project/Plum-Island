# Getting Started

This guide walks you through your first scan end-to-end, from adding a target to reading results.

## General overview

Plum Island is not the scanner itself. Plum Island is the orchestrator and data analyzer.

Scans are executed by [Plum Pathogen Agent](https://github.com/D4-project/Plum-Agent). Agents request jobs from Plum Island, consume them, run the scans, and send the results back. Plum Island decides when jobs should be made available, keeps the queue under control, and analyzes the collected data.

Plum Island does not schedule scans at fixed times. It schedules the time between scans. This is part of its design philosophy.

The internal scheduler runs periodically and feeds the job queue for agents to consume. The default scheduler interval is 10 minutes. The scheduler does not fill the queue with all jobs at once; it keeps the queue sufficiently filled for agent consumption without overloading the system. After adding a target or scan profile, you may not see jobs immediately.

If you need more aggressive timing for a lab or demo, update `SCHEDULER_DELAY` in `webapp/config.py`. For daily or weekly scans, this is usually unnecessary. This behavior allows Plum Island to manage more than 10 million scan jobs while keeping resource usage low.

## Prerequisites

- The Plum Island stack is running and reachable at `http://localhost:5000`. See the [installation documentation](installation.md) for install instructions.
- You have admin credentials. Docker deployments print generated credentials on first start:

```
[plum] =================================================
[plum]  Admin user    : admin
[plum]  Admin password: <generated>
[plum] =================================================
```

## Step 1 — Add a target

1. Navigate to `Config > Targets`.
2. Click `+` to open the new target form.
3. Set the `CIDR / Host` field to an address range or hostname you are authorized to scan (e.g. `192.168.1.0/24` or an internal hostname).
4. Select a **Scan Profile**. The `Default banner scan` profile is available out of the box and scans TCP ports `22`, `80`, and `443` with `banner.nse`.
5. Save the record.

Plum Island will make jobs available for active `Target x ScanProfile` combinations when the scheduler runs. You can watch queued and completed jobs under `Status > Job Status`.

## Step 2 — Create an agent API key

Scans are executed by Plum Pathogen Agent, not by the web application itself. The agent authenticates with an API key.

1. Navigate to `Security > Agent Keys`.
2. Click `+` to generate a new key.
3. Add a short description (e.g. `lab agent`, `docker agent`) so you can identify the key later.
4. **Copy the key immediately.** It is only shown at creation time; Plum Island stores a hashed copy afterwards.
5. Save the record.

## Step 3 — Connect a Plum Pathogen Agent

Install and start a [Plum Pathogen Agent](https://github.com/D4-project/Plum-Agent) using the key from Step 2.

### Native (Python)

Follow the setup instructions in the Plum Agent repository, then run:

```bash
python agent.py
```

Set the Island URL and your key in the agent configuration as documented in its README.

### Docker

If you are running Plum Island with Docker Compose, start the Island stack first:

```bash
# Plum Island directory
docker compose up -d
```

Then start the Plum Agent container or compose stack and point it at an Island URL reachable from the agent:

```bash
PLUM_ISLAND=http://<island-host>:5000
AGENT_KEY=<key from Step 2>
```

If the agent runs in another Docker Compose stack, both stacks must share a network before the agent can use an internal service name. Otherwise, use the host or IP address that exposes Plum Island on port `5000`.

```bash
# Plum Agent directory, if using its compose stack
docker compose up -d
```

Once the agent is running it appears in `Status > Bot Status`.

## Step 4 — View results

The agent polls for pending jobs, executes the scans, and submits results back to the Island.

1. Go to `Status > Job Status` to watch the job move from queued to finished.
2. When the job completes, click the **magnifying glass** icon on that row to open the job detail view.
3. The **Show Results** panel displays the full parsed scan output.

For richer search and filtering across all collected scan data, use `Analytics > Search Scans` or see the [search documentation](search.md).
