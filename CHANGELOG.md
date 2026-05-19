# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/) (`0.YYMM.MICRO`).

## [Unreleased]

### Added
- Detection tags: Dropbear SSH, FRITZ!Box SIP, Microsoft SMTP gateway
- Detection tags: SIP protocol (#26)
- Detection tags: CrushFTP server header (#38)
- Detection tags: Red Hat Enterprise Linux HTTP server header in Apache RedHat detection (#39)
- Detection tags: NetScaler AAA title and LogonPoint path tagging (#40)
- Detection tags: Netskope Borderless SD-WAN certificate issuer tagging (#41)
- Detection tags: WatchGuard Fireware XTM favicon, title, and certificate tagging (#42)
- Detection tags: Cisco Catalyst SD-WAN title and certificate tagging (#43)
- Detection tags: ProFTPD (#36)
- Detection tags: Pure-FTPd (#35)
- Detection tags: pfSense (#34)
- Detection tags: Mitel 108 (#30)
- Detection tags: Dovecot (#28)
- Detection tags: Raspberry/Raspbian HTTP and SSH tagging (#25)
- Detection tags: Zyxel USG20 plus separate Zyxel SSH rule (#32)
- Detection tags: `soft:ssh` on all SSH banner detections
- Detection tags: Drupal x-generator header value tagging (#56)
- Detection tags: WordPress redirect and powered-by header value tagging with PHP classification (#57)
- Detection tags: PHP and Ubuntu x-powered-by header value tagging (#62)
- Detection tags: Joomla x-content-encoded-by header value tagging (#59)
- Detection tags: OWA x-owa-version header tagging (#60)
- Detection tags: Polylang x-redirect-by header value tagging (#61)
- Detection tags: generic HTTP banner/header protocol tagging (#64)
- Detection tags: ASP.NET favicon detection and header tagging (#63)
- Detection tags: LiteSpeed header tagging (#58)
- Detection tags: Cisco Expressway server header tagging (#78)
- Detection tags: BGP protocol banner tagging (#71)
- Detection tags: HP iLO default certificate issuer tagging (#73)
- Detection tags: Cisco router detection with IOS server and authentication realm tags (#79)
- Detection tags: generic OpenSSH banner tagging, `soft:openssh` on OpenSSH-derived rules
- Detection tags: SSH banner rules for Cerberus FTP Server, MOVEit Transfer SFTP
- Detection tags: SSH banner rules for Serv-U FTP Server and WS_FTP SSH
- Detection tags: NetScreen SSH banner tagging
- Detection tags: Cisco and Lancom SSH banner tagging; Zyxel SSH classified as router hardware
- Detection tags: SFTPGo and Bitvise SSH Server banner tagging
- Detection tags: Crestron SSH banner tagging
- Detection tags: generic FTP welcome banner tagging
- Detection tags: Microsoft FTP Service banner tagging
- Detection tags: FileZilla FTP Server banner tagging
- Detection tags: vsftpd FTP banner tagging
- Detection tags: Mikrotik FTP banner tagging
- Detection tags: QNAP NASFTPD/ProFTPD FTP banner tagging
- Detection tags: Debian ProFTPD FTP banner tagging
- Detection tags: `import_tags.py --flush-tag` to remove one tag from Kvrocks tag indexes (#47)
- Scan profile cycle tracking with current and previous cycle visibility (#52)
- Curated HTTP header presence/value collection and structured Kvrocks search (#54)
- Required tool dependency update

### Changed
- Scheduler FQDN/IP job batching now fills 256-item packets when due targets remain (#51)
- Bump MixVoip tag rule version to force corrected `soft:telephony` import (#48)
- Normalize Apache favicon-derived tag names/tags; merge Tomcat favicon detection (refs #50)
- Normalize Cisco, Check Point, Debian, and Gargoyle tag rule names/tags (refs #50)
- Normalize Arris favicon-derived rule names/tags as router hardware (refs #50)
- Merge SonicWall favicon-derived rules into the main SonicWall rule (refs #50)
- Normalize Zyxel tag rule names/tags as Zyxel hardware (refs #50)
- Merge Windows OpenSSH version-specific banner rules into one generic rule (refs #50)
- Merge Joomla favicon rules (refs #50)
- Merge OWA favicon rules (refs #50)
- Merge ASP.NET favicon detection rules (refs #63)
- Replace SSH software tag with `proto:ssh`; tighten generic SSH banner tagging (#65)
- Rename detection tag prefixes from `hard`/`soft` to `tag:vendor`/`tag:product` (refs #50)
- Complete tag taxonomy normalization for vendor/product/type/protocol tags (#50)
- Rename Mikrotik tag rule file from `microtik` to `mikrotik` (refs #50)
- Improve Kvrocks rebuild tooling: direct Meili rebuild, multiprocessing parser workers, retag mode, graceful Ctrl+C, quieter logs, and progress output
- Split tools Meilisearch config into `IN_MEILI_*` and `OUT_MEILI_*`; remove legacy `MEILI_*` tool config keys
- Rework `index_meili.py` to import dumps into `OUT_MEILI_*` with batching and optional `--progress`
- Show inserted Tag Rule IDs in `import_tags.py`
- Make bot job submission idempotent
- Prevent concurrent scanner agents from claiming the same queued job

### Fixed
- `import_tags.py` now updates DB tag rules from newer YAML versions and prints existing rule IDs (#49)
- Harden job result rendering against banner HTML injection (#37)


## [0.2604.0] - 2026-04-01

### Added
- IP detail view with per-port scan history, timestamp tabs, vhost filtering, PTR hostnames, certificate details, and quick service links
- Passive DNS and CIRCL geolookup enrichment in IP detail
- Tag Rules with YAML-backed signatures, automatic Kvrocks tagging, and import/export support
- Large built-in technology fingerprint library
- Configurable scan profiles with ports, NSE scripts, target bindings, scan cycles, and priorities
- Target/profile scan state tracking with working state, last scan, previous scan, and cycle duration
- Scheduled Markdown reports with asynchronous preview and manual run support
- Controller-managed NSE scripts deployed to agents with hash-based cache synchronization
- `OR`, `since:N`, `fqdn_requested`, `domain_requested`, `tag`, favicon hash, and banner search capabilities
- Asynchronous search result download for IP lists and full JSON exports
- Stats dashboard for targets, estimated scan scope, and object counts
- Read-only security role template
- Documentation for many topics
- TLD validation using faup-rs lib or data.iana.org
- IP detail hostname from target details for FQDN targets
- IP detail hostname from KV search using requested hostnames stored in Kvrocks
- Tool script for PDNS hosts extraction `last_fqdns.py`
- Tool script for API target import

### Changed
- Improve structured search page

### Fixed
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

### Known Limitations
- Only TCP supported
- IPv6 scan not supported yet


## [0.2510.0] - 2025-10-01

### Added
- Initial Plum Island orchestration server
- Target and job storage with Flask-AppBuilder UI
- Remote agent job dispatch and scan result collection
- Historical scan result storage
- Meilisearch and Kvrocks-backed search
- Structured search keywords: `ip`, `net`, `fqdn`, `host`, `domain`, `tld`, `port`, `http_*`, `x509_*`
- Search modifiers: `like`, `begin`, plus `lk` and `bg` abbreviations
- Basic installation flow with `setup.sh`


[Unreleased]: https://github.com/D4-project/Plum-Island/compare/v0.2604.0...HEAD
[0.2604.0]: https://github.com/D4-project/Plum-Island/compare/v0.2510.0...v0.2604.0
[0.2510.0]: https://github.com/D4-project/Plum-Island/releases/tag/v0.2510.0
