
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
| fqdn | like, begin| fully qualified domain name|
| host | like, begin  | hostname, the subdomain part |
| domain | like, begin | dns domain |
| tld | like, begin | top level domain | 
| port | | Open port |
| http_title | like, begin | html title tag |
| http_cookiename | like, begin | Http set cookie keyname |
| http_etag | like, begin | http etag value |
| http_server | like, begin | http serveur value |
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

### Example of query

>domain.begin:"circl.lu" port:443 http_server.lk:nginx

Retrieve all Nginx http servers listening on port 443, with any mention to domain belonging to CIRCL.lu

### Example with OR

>http_server.lk:nginx OR http_server.lk:apache

Retrieve hosts matching either nginx or apache.

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
