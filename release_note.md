# Plum Island - MarmotUp Release - v0.2604.0 Latest

Nearly ready for production.

## New Feature
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

## Current Limitation
- Only TCP Supported.
- IPv6 scan not supported yet.


## Bugfix
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
