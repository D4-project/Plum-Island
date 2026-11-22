# Network requirements and data flows

This page describes the connections initiated by Plum-Island and its clients.
Ports below are destination ports and shipped defaults unless stated otherwise;
adapt them to your configured endpoints. Arrows show who initiates a connection;
responses travel back over that connection. They are not additional inbound
listeners.

## General topology

```text
 Users / browser          Plum-Agent scanners           API / import clients
       |                         |                              |
       | UI + downloads          | beacon / getjob / sndjob      | API
       +-------------------------+------------------------------+
                                 |
                  Configured Island URL (HTTP or HTTPS)
                                 |
                   [Optional TLS reverse proxy :443]
                                 |
                                 v
                     +-------------------------+
                     | Plum-Island :5000/TCP   |
                     | Web UI + API + scheduler|
                     +-------------------------+
                       |        |        |
          HTTP :7700 ---+        |        +--- local files
                 |              |             SQLite app.db
                 v              |             raw JSON / exports / PDFs
          [Meilisearch]          |
          Scan documents        +--- TCP :6666 ---> [Kvrocks]
                                                   Search index + history

 Plum-Island outbound connections
       +-- HTTPS :443 --> ip.circl.lu (AS / country / routing information)
       +-- HTTPS :443 --> www.circl.lu (optional authenticated Passive DNS)
       +-- DNS :53 ----> configured resolver (UDP + TCP)
       +-- TCP :43 ----> IANA / RIR / domain WHOIS registries (on demand)
       +-- SMTP ------> configured mail relay (optional report delivery)

 Plum-Agent -- configured scan traffic --> authorized targets
 Browser    -- HTTPS :443 --------------> geo.circl.lu (optional map tiles)
 Browser    -- Open web service --------> selected target and scanned port
```

The reverse proxy is an operator-provided component, not part of the shipped
Compose stack. Direct/demo access uses HTTP on TCP 5000. See the
[installation runtime limitations](installation.md) before exposing the launcher.
Scanners poll Island and upload their results: Island does not initiate a
connection to a scanner listener. Scanners do not need direct backend access.
SQLite and scan files are local storage, not extra network services by default.

## Incoming connections

| Source | Destination | Protocol / port | Purpose |
| --- | --- | --- | --- |
| Users, API consumers and import clients | Configured Island URL | HTTP TCP 5000 directly, or the configured proxy port (typically HTTPS TCP 443) | UI, authenticated API, exports and reports |
| Plum-Agent | Same Island URL | Same configured HTTP(S) endpoint | `/bot_api/beacon`, `/bot_api/getjob`, `/bot_api/sndjob`, `/bot_api/releasejob`; jobs, NSE scripts, results and interrupted-job release use the API |
| Reverse proxy, if deployed | Island application | HTTP TCP 5000 by default | Forward application requests |
| Island and explicitly authorized maintenance hosts | Meilisearch | HTTP TCP 7700 by default | Read/write scan documents; `MEILI_DATABASE_URI`, `MEILI_KEY` |
| Island and explicitly authorized maintenance hosts | Kvrocks | TCP 6666 by default | Read/write the structured search index and observation history; `KVROCKS_HOST`, `KVROCKS_PORT` |

Backend ports are not browser or scanner prerequisites. In the shipped
`docker-compose.yml`, **5000, 7700 and 6666 are published on the Docker host**.
Only `plum-webapp` joins the external `plum_net`; both backends use the Compose
default network. That separation does not cancel their published host ports.
Account for these bindings in your deployment's access policy.

## Outgoing runtime connections from Island

| Destination | Protocol / port | Used by / configuration | Effect when unavailable |
| --- | --- | --- | --- |
| Meilisearch | HTTP TCP 7700 by default | `MEILI_DATABASE_URI`, `MEILI_KEY`; UI document retrieval and scheduler export | Documents cannot be retrieved/exported normally |
| Kvrocks | TCP 6666 by default | `KVROCKS_HOST`, `KVROCKS_PORT`; search, tags, histories and indexing | Structured search/history and indexing are affected |
| `ip.circl.lu` | HTTPS TCP 443 | `/geolookup/<ip>`; no API key; IP view, target enrichment and routing checks | Missing/stale target routing data can defer CIDR job creation; failed lookup is not ASN 0 |
| `www.circl.lu` | HTTPS TCP 443 | `/pdns/query/<ip>`; `PASSIVE_USER`, `PASSIVE_PWD`; IP view and reports | Passive DNS enrichment unavailable; omitted when disabled |
| Configured DNS resolver | UDP and TCP 53, for a conventional resolver | OS/container name resolution; Active DNS uses `dnspython` and the system resolver configuration | Hostname-based services and live A-record checks can fail |
| `whois.iana.org` | TCP 43 | First hop for an uncached IP/CIDR lookup or a domain WHOIS query | Fresh WHOIS lookups fail |
| `whois.afrinic.net`, `whois.apnic.net`, `whois.arin.net`, `whois.lacnic.net`, `whois.ripe.net` | TCP 43 | Network WHOIS, including inter-RIR referrals | Relevant network WHOIS lookups fail |
| Domain registry returned by IANA | TCP 43 | FQDN WHOIS, after offline extraction of the registrable domain; validated public `whois.*` referral | Relevant domain WHOIS lookups fail; the five RIR hosts alone are insufficient |
| Configured SMTP relay | TCP `REPORT_SMTP_PORT` (default 25) | `REPORT_SMTP_HOST`; STARTTLS or implicit TLS according to report configuration | Report email delivery fails; PDF generation is local |

SMTP ports such as 587 (STARTTLS) or 465 (implicit TLS) must be configured
explicitly; enabling a TLS flag does not select a different port automatically.
See [report mail configuration](reports.md).

Plum checks its shared Kvrocks cache before querying IP/AS information (default
24 hours), IP/CIDR WHOIS (24 hours) or authenticated Passive DNS (12 hours).
A fresh hit avoids the corresponding outbound lookup. Reports and the IP view
reuse the same Passive DNS responses. Target routing uses the IP/AS lifetime
to decide when to refresh. With no fresh routing data, a failed refresh defers
scheduling. A successful ASN 0 means the CIDR is unannounced.
See [cache internals](sysinternal/caching.md) and [target routing](scanning.md#target-metadata-and-network-information).

### WHOIS for IPs, networks and domains

The analyst’s browser calls Plum over its normal HTTP(S) endpoint. Only the
Island server needs outbound TCP 43 and DNS resolution for registry hostnames.

- **IP or CIDR.** The WHOIS tab and the enabled Location map share the IP
  lookup. On a cache miss, Island sends the canonical network to
  `whois.iana.org` and follows referrals to the regional registries listed
  above. An address transfer can require a second regional registry.
- **Domain target.** Island extracts the registrable domain locally, asks IANA
  about the top-level domain, then queries the public `whois.*` host named in
  the referral. This path does not use the IP/CIDR WHOIS cache.

Active DNS uses Island’s configured resolver. Domain suffix extraction uses
the bundled `pyfaup` data offline.

## Browser and scanner traffic

- **Location map.** With **Security → Plum Settings → IP detail map → Show location
  map** enabled (default), opening **Informations** on an IP page requests WHOIS
  and IP/AS data from Island. The marker uses WHOIS `geoloc` when available,
  then falls back to the country’s average coordinates. Once a position exists,
  the **browser** fetches tile images from `https://geo.circl.lu/hot/{z}/{x}/{y}.png`
  over **TCP 443**. The URL contains the zoom level and tile coordinates.
  If a proxy enforces a Content Security Policy, allow `https://geo.circl.lu`
  in `img-src`. Blocking tile access leaves the map background blank. Turning
  the map off and restarting Plum-Agent removes the tile requirement. The WHOIS
  tab and IP/AS panels remain available.
- Clicking **Open web service** makes the browser contact the selected hostname
  or IP using the selected observation's HTTP(S) scheme and scanned port, which
  may differ from 80/443. This is not an Island-server fetch.
- Vendor-tag links open `https://vulnerability.circl.lu/` in the browser.
- Scanners need access to Island, DNS and the authorized target ports/protocols
  required by their scan profiles and NSE scripts. Their scan traffic is distinct
  from Island's enrichment traffic; there is no fixed list of scan destination
  ports. Use the [agent documentation](https://github.com/D4-project/Plum-Agent)
  for scanner-specific deployment requirements.
- Masscan sends raw scan packets directly from the agent host. On Linux the
  Masscan executable needs `CAP_NET_RAW` (or the agent must run as root, which is
  not recommended). Stateful firewalls, source-address policy and return traffic
  must permit the selected targets, ports and packet rate. Protocol detection
  adds response exchanges for supported banners but no new Island connection.

## Installation, updates and optional tools

These flows originate on the host/container running the command, not necessarily
the web application host, and need not be permanent runtime access:

- Git checkout/submodules and NSE synchronization contact GitHub. HTTPS clones
  use TCP 443; an SSH remote uses its configured SSH endpoint (normally TCP 22).
  `initial_setup.py` retrieves `D4-project/Plum-Rules-NSE` over HTTPS by default.
- Python installation contacts the configured package index and artifact hosts
  (normally PyPI over HTTPS). Docker builds also need the configured image
  registry and OS package repositories. Allow mirrors/redirect destinations used
  by your package configuration; `github.com` alone is not sufficient.
- Export/reindex/migration commands need access to their configured `IN_*` and
  `OUT_*` Meilisearch/Kvrocks services. They do not necessarily use the webapp's
  endpoints. Import clients also contact the configured Island API.
- `tools/import_whois_ranges.py` downloads selected RIR datasets. Current sources
  include FTP on `ftp.afrinic.net`, `ftp.apnic.net`, `ftp.lacnic.net` and
  `ftp.ripe.net`, and HTTPS on `ftp.arin.net`. FTP needs TCP 21 plus passive data
  connections to server-selected ports; allowing only TCP 21 is insufficient.
  This bulk download is distinct from interactive WHOIS on TCP 43.
- Optional external authentication or a non-SQLite SQLAlchemy database adds
  deployment-specific connections; the default configuration uses local DB auth
  and SQLite. Include those destinations if you enable them.

## Deployment verification

Check connectivity from the actual runtime network namespace (inside
`plum-webapp` for Compose), not just from an administrator's workstation:

1. Confirm Island can reach both configured backends and perform authenticated
   operations; a successful TCP connection alone does not validate credentials.
2. Confirm scanners can poll Island and upload results through any proxy, with
   request size/time limits appropriate for scan JSON.
3. Check CIRCL routing enrichment, optional Passive DNS, DNS resolution, WHOIS
   and SMTP separately. HTTP proxies do not automatically carry DNS, WHOIS,
   Kvrocks or SMTP traffic.
4. From the analyst’s browser, open **Informations** for an IP with coordinates.
   In the Network panel, confirm image requests to `geo.circl.lu/hot/…` succeed.
   Test WHOIS separately on its own tab. A fresh cached result verifies the UI
   but does not exercise the server’s TCP 43 path.
5. Confirm browser-originated target links work from the analyst’s network.
# Masscan banner source

Banner jobs use the dedicated `masscan_ip` announced by Plum-Agent at startup.
Reserve an unused address on the scanner's local subnet, outside the host's
kernel interfaces. Permit return traffic to that address on the scanning network.
The operator must verify address ownership, uniqueness and return routing.
Configure it with `python agent.py -s --masscan-ip ADDRESS` and restart the agent.
Source and targets must use the same IP family. Island dispatches banner jobs
only to agents announcing a dedicated source address.
