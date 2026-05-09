# Plum Island - Next Release - Unreleased

Changes after `v0.2604.0`.

## Changes
- Detection tags:
  - Dropbear SSH (`eac052b`), FRITZ!Box SIP (`ff2fcc6`), Microsoft SMTP gateway (`b19b027`)
  - SIP protocol, closes #26 (`0227c6a`)
  - CrushFTP server header, closes #38 (`b41e40f`)
  - Red Hat Enterprise Linux HTTP server header in Apache RedHat detection, closes #39
  - NetScaler AAA title and LogonPoint path tagging, closes #40
  - Netskope Borderless SD-WAN certificate issuer tagging, closes #41
  - WatchGuard Fireware XTM favicon, title, and certificate tagging, closes #42
  - Cisco Catalyst SD-WAN title and certificate tagging, closes #43
  - Scheduler FQDN/IP job batching now fills 256-item packets when due targets remain, closes #51
  - ProFTPD, closes #36 (`3e4f7a2`)
  - Pure-FTPd, closes #35 (`d019905`)
  - pfSense, closes #34 (`6b609d9`)
  - Mitel 108, closes #30 (`0c019fa`)
  - Dovecot, closes #28 (`63e2001`)
  - Raspberry/Raspbian HTTP and SSH tagging, closes #25 (`2f618ba`, `b2c9b5e`)
  - Zyxel USG20 plus separate Zyxel SSH rule, closes #32 (`98e6e75`, `a2e0f95`)
  - Add `soft:ssh` to all SSH banner detections (`d8b16d2`)
  - Bump MixVoip tag rule version to force corrected `soft:telephony` import, closes #48
  - Normalize Apache favicon-derived tag names/tags and merge Tomcat favicon detection, refs #50
  - Normalize Cisco, Check Point, Debian, and Gargoyle tag rule names/tags, refs #50
  - Normalize Arris favicon-derived rule names/tags as router hardware, refs #50
  - Merge SonicWall favicon-derived rules into the main SonicWall rule, refs #50
  - Normalize Zyxel tag rule names/tags as Zyxel hardware, refs #50
  - Validate Ubuntu/Debian SSH banner tagging for OpenSSH package banners, refs #50
  - Merge Windows OpenSSH version-specific banner rules into one generic rule, refs #50
  - Add generic OpenSSH banner tagging and include `soft:openssh` on OpenSSH-derived rules, refs #50
  - Add generic SSH protocol banner tagging for `ssh-2.0` banners, refs #50
  - Add SSH banner rules for Cerberus FTP Server and MOVEit Transfer SFTP, refs #50
  - Add SSH banner rules for Serv-U FTP Server and WS_FTP SSH, keeping Serv-U web favicon separate, refs #50
  - Add NetScreen SSH banner tagging, refs #50
  - Add Cisco and Lancom SSH banner tagging, and classify Zyxel SSH as router hardware, refs #50
  - Add SFTPGo and Bitvise SSH Server banner tagging, refs #50
  - Add Crestron SSH banner tagging, refs #50
  - Add generic FTP welcome banner tagging for FTP server/service banners, refs #50
  - Add Microsoft FTP Service banner tagging, refs #50
  - Add FileZilla FTP Server banner tagging, refs #50
  - Add vsftpd FTP banner tagging, refs #50
  - Rename Mikrotik tag rule file typo from `microtik` to `mikrotik`, refs #50
  - Add Mikrotik FTP banner tagging, refs #50
  - Add QNAP NASFTPD/ProFTPD FTP banner tagging, refs #50
  - Add Debian ProFTPD FTP banner tagging, refs #50
  - Add Drupal x-generator header value tagging, closes #56
  - Add WordPress redirect and powered-by header value tagging with PHP classification, closes #57
  - Add PHP and Ubuntu x-powered-by header value tagging, closes #62
  - Merge Joomla favicon rules and add x-content-encoded-by header value tagging, closes #59
- Make bot job submission idempotent (`ac9c7fe`)
- Prevent concurrent scanner agents from claiming the same queued job
- Add scan profile cycle tracking with current and previous cycle visibility, closes #52
- Add curated HTTP header presence/value collection and structured Kvrocks search, closes #54
- Improve Kvrocks rebuild tooling: direct Meili rebuild, multiprocessing parser workers, retag mode, graceful Ctrl+C, quieter logs, and progress output (`23b9d83`)
- Split tools Meilisearch config into `IN_MEILI_*` and `OUT_MEILI_*`; remove legacy `MEILI_*` tool config keys (`ef4ceec`)
- Rework `index_meili.py` to import dumps into `OUT_MEILI_*`, with batching and optional `--progress` (`ef4ceec`)
- Show inserted Tag Rule IDs in `import_tags.py` (`bf1afd5`)
- Add `import_tags.py --flush-tag` to remove one tag from Kvrocks tag indexes, closes #47
- Fix `import_tags.py` to update DB tag rules from newer YAML versions and print existing rule IDs, closes #49
- Add required tool dependency update (`acbe2d1`)
- Harden job result rendering against banner HTML injection, closes #37 (`7224443`)

# Plum Island - MarmotUp Release - v0.2604.0

Nearly ready for production.

## v0.2604.0 Highlights
- IP detail view with scan history, vhost filtering, PTR hostnames, cert details, and quick service links
- Passive DNS and CIRCL geolookup enrichment
- YAML-backed Tag Rules, automatic Kvrocks tagging, and import/export support
- Built-in technology fingerprint library
- Configurable scan profiles, priorities, target bindings, and scan cycles
- Target/profile scan state tracking
- Scheduled Markdown reports with async preview and manual runs
- Controller-managed NSE scripts deployed to agents
- Expanded structured search: `OR`, `since:N`, requested FQDN/domain, tags, favicon hashes, and banners
- Async search result downloads for IP lists and full JSON exports
- Stats dashboard and read-only security role template
- TLD validation via faup-rs or IANA data

## v0.2604.0 Features
- Add IP detail view with per-port scan history, timestamp tabs, vhost filtering, PTR hostnames, certificate details, and quick service links
- Add Passive DNS and CIRCL geolookup enrichment in IP detail
- Add Tag Rules with YAML-backed signatures, automatic Kvrocks tagging, and import/export support
- Add a large built-in technology fingerprint library
- Add configurable scan profiles with ports, NSE scripts, target bindings, scan cycles, and priorities
- Add target/profile scan state tracking with working state, last scan, previous scan, and cycle duration
- Add scheduled Markdown reports with asynchronous preview and manual run support
- Add controller-managed NSE scripts deployed to agents with hash-based cache synchronization
- Improve structured search page
- Add `OR`, `since:N`, `fqdn_requested`, `domain_requested`, `tag`, favicon hash, and banner search capabilities
- Add asynchronous Search result Download function for IP lists and full JSON exports
- Add stats dashboard for targets, estimated scan scope, and object counts
- Add read-only security role template
- Add documentation for many topics
- Validate TLD using faup-rs lib or data.iana.org
- Add IP detail hostname from target details for FQDN targets
- Add IP detail hostname from KV search using requested hostnames stored in Kvrocks
- Add tool script for PDNS hosts extraction last_fqdns.py
- Add tool script for API target import

## v0.2604.0 Current Limitation
- Only TCP Supported.
- IPv6 scan not supported yet.


## v0.2604.0 Bugfix
- Improve document storage to avoid lock
- Add cleanup of old jobs
- Add index for scan timeline
- Refactor scheduler job generation to reduce SQLite lock contention
- Add weighted priority queues and queued-job priority retagging for scan profiles
- Add batched orphan working-state repair for target scan states
- Harden bot job ownership checks on `/bot_api/getjob` and `/bot_api/sndjob`
- Throttling of bot job submissions
- Prevent stale Flask-Login sessions from crashing when a user no longer exists
- Add missing Flask-AppBuilder access checks on Tag Rules export routes
- Escape dynamic HTML helper output in models to reduce stored XSS risk

# Plum Island - Hack.lu Release - v0.2510.0

Initial public release for Hack.lu.

## New Feature
- Initial Plum Island orchestration server
- Target and job storage with Flask-AppBuilder UI
- Remote agent job dispatch and scan result collection
- Historical scan result storage
- Meilisearch and Kvrocks-backed search
- Structured search keywords: `ip`, `net`, `fqdn`, `host`, `domain`, `tld`, `port`, `http_*`, `x509_*`
- Search modifiers: `like`, `begin`, plus `lk` and `bg` abbreviations
- Basic installation flow with `setup.sh`
