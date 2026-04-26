
<div align="center">
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_logo.png"   style="width:25%;" />

<h1> Proactive Land Uncovering & Monitoring </h1>
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_overview.png" />
</div>
<p>
<center>
*Beta version*
</center>
</p>

## Description

This tool acts as an orchestrator for proactive surface-exposure discovery.
It assigns scanning tasks to agents, collects their results, and stores the data with full history. The collected information is queryable.

## Scan statistics model

Scheduling is done per `Target x ScanProfile`.
This means one target can have multiple independent scan states at the same time, one for each effective profile.

### Per-profile stats

The authoritative runtime stats are stored in `target_scan_states` and visible in:

- `Status -> Profile Scans`
- the `Profile Scan Stats` table on `/targetsview/show/<id>`

For each `target/profile` pair, the following values are tracked:

- `working`: at least one job for this target/profile is still running or pending
- `last_scan`: completion time of the latest finished scan cycle for this target/profile
- `last_previous_scan`: completion time of the previous finished scan cycle for this target/profile
- `cycle`: time delta between `last_scan` and `last_previous_scan`

### Scan execution parameters

Ports and NSE scripts are now resolved exclusively from the effective `ScanProfile`.
There is no longer a global fallback list in `config.py`.

When a bot fetches a job:

- `nmap_ports` comes only from the job/profile
- `nmap_nse` comes only from the job/profile
- NSE files are synchronized to the agent by filename and SHA-256 hash
- the file body is only transferred when the agent cache does not already have the expected hash

### Global target stats

The legacy fields on `targets` are still kept as global aggregates:

- `Targets.working`: `True` if any profile for this target is currently working
- `Targets.last_scan`: completion time of the latest finished profile on this target
- `Targets.last_previous_scan`: previous value of the global `last_scan`
- `Targets.duration_html()`: delta between the 2 global timestamps above

Important: these global values do **not** represent a full multi-profile scan cycle anymore.
They only represent the last scan event observed on the target, regardless of which profile produced it.
For operational tracking, always prefer the per-profile stats.

## Search capacity

The following keywords can be used to explore the data:

| Keyword | Modifier | Description |
| -------- | -------- | -------- |
| ip     |      | IP of the host  |
| net | | Cidr network, from /16 to /24 |
| fqdn | like, begin| Fully qualified domain name found |
| fqdn_requested | like, begin | FQDN given to scanner |
| domain_requested | like, begin | Domain given to scanner |
| host | like, begin  | hostname, the subdomain part |
| domain | like, begin | dns domain |
| tld | like, begin | top level domain | 
| tag |  | Computed document tag |
| port | | Open port |
| http_title | like, begin | html title tag |
| http_cookiename | like, begin | Http set cookie keyname |
| http_etag | like, begin | http etag value |
| http_server | like, begin | http serveur value |
| http_favicon_path | like, begin | favicon source path |
| http_favicon_mmhash | | favicon MurmurHash value |
| http_favicon_md5 | | md5sum of the favicon |
| http_favicon_sha256 | | sha256sum of the favicon |
| banner | like, begin | Services banner server value |
| x509_issuer | like, begin | 
| x509_md5 | | md5sum of the tls  certificate public signature   
| x509_sha1 | | sha1sum of the tls certificate public signature | 
| x509_sha256 | | sha256sum of the tls certificate public signature | 
| x509_subject |like, begin | tls certificate common name  |
| x509_san |like, begin |  tls certificate subject alternatives name |

modifier could be abreviated;  
* like to lk
* begin to bg

The query string supports `AND` by default between terms inside one group.
You can also use explicit `OR` between groups.

The structured search page also applies a date range:

- by default, from today back to today minus 3 months
- start date is evaluated at `00:00:00`
- end date is evaluated at `23:59:59`

For responsiveness, the UI shows the first 100 matching IPs, then continues with `Load more`.
The visible page scans recent history first and grows the inspected time window when needed.
Exports still run on the full filtered result set, not only on the currently visible 100 results.

### Example of query

>domain.begin:"circl.lu" port:443 http_server.lk:nginx

Retrieve all Nginx http servers listening on port 443, with any mention to domain belonging to CIRCL.lu

### Example with OR

>http_server.lk:nginx OR http_server.lk:apache

Retrieve hosts matching either nginx or apache.

### Example with requested FQDN

>fqdn_requested.lk:ttrenov.lu port:443

Retrieve hosts where the user-requested hostname matches `ttrenov.lu` and port 443 is open.

## Job priority

Scan profiles and jobs support five priority queues:

- `0`: background
- `1`: low
- `2`: normal
- `3`: high
- `4`: urgent

New jobs inherit the priority of their scan profile.
The `Priority Boost` action on an existing job raises it to priority `4`.
When a scan profile priority changes, already queued unfinished jobs are retagged gradually by the scheduler.
`SCHEDULER_PRIORITY_RETAG_BATCH_SIZE` controls how many queued jobs are updated per profile and scheduler tick.
`SCHEDULER_ORPHAN_SWEEP_BATCH_SIZE` controls how many stuck target/profile working states are repaired per orphan sweep.

When agents request work, Plum uses a dynamic weighted round-robin over the queues that currently have waiting jobs. The base weights are:

| Priority | Weight |
| -------- | ------ |
| 4 | 50 |
| 3 | 20 |
| 2 | 15 |
| 1 | 10 |
| 0 | 5 |

Only non-empty queues are considered, so if urgent/high queues are empty the remaining capacity is redistributed across the lower queues instead of being pinned to a fixed fallback order.

## Reports

Plum can generate scheduled Markdown reports from the same structured Kvrocks query syntax used by Header Search.

A report is configured with:

- a name and description
- a structured search query
- one or more recipient emails
- a monthly schedule
- a `Report active` flag

`Report active` only controls automatic scheduled delivery. Preview and manual `Run now` actions remain available for inactive reports.

### Report interval

Report queries are always executed inside the report interval.

For monthly reports:

- if the report has already run, the interval starts at `last_run_at`
- if the report has never run, the interval starts one calendar month before the run time
- the interval ends at the current run time

The query is the business filter, while the report interval is the time filter imposed by reporting.

### Markdown content

Reports are generated as Markdown. The current report body contains:

- report summary
- query and reporting period
- number of matching IPs and scan results
- open port summary
- `New opened port`, comparing the current monthly interval with the previous monthly interval
- host list sorted by numeric IP order
- per-host tags when present
- per-host open ports and scan result count
- per-host associated FQDNs from report PTR records seen in the last 6 months, then `fqdn_requested`, completed with Passive DNS `A` records up to 25 entries
- an as-is disclaimer

Example host entry:

```md
- 158.64.1.27
  - Tag: vuln:filelisting
  - Open ports: 443
  - Scan results: 1
  - Associated FQDNs (3)
    - reverse.example.org (ptr)
    - scan-request.example.org
    - historical.example.org (pdns)
```

### Preview generation

The `Preview` action generates the Markdown report without sending email.
Because Passive DNS enrichment can be slow, preview first opens a progress modal and only redirects to the rendered report when generation is complete.

The modal follows the report generation order:

- `Generating monthly report`
- `Comparing with previous report`
- `Resolving Passive DNS X/XX`

### Email delivery

SMTP delivery is controlled by the `REPORT_SMTP_*` settings in `webapp/config.py`.
If `REPORT_SMTP_HOST` is empty, automatic report delivery is disabled.

`REPORT_PTR_LAST_SEEN_MONTHS` controls how recent a source document must be for its PTR hostname to appear in a report. The default is 6 months before the report end time.

## Technical requirements

- Python 3.10 
- Flask Appbuilder 4.8 (https://flask-appbuilder.readthedocs.io/en/latest/#) 
- meilisearch (https://www.meilisearch.com/) 
- Kvrocks (https://kvrocks.apache.org/) 

## Installation

Before starting the setup, please ensure that you have both a meilisearch and a kvrocks servers running and reachable.

To setup an environnement do;

```bash
git clone 
cd Plum-Island 
./setup.sh 
```
And review config.py for matching your configuration 

Then you could setup your prefered web server or simply run for demo
```bash
source ./venv/bin/activate  
cd webapp  
python run.sh  
```
