# Historical date-only duplicate recovery

Status: `migrate_smarthash.py` implements preparation and explicit OUT replacement.
See `documentation/tools.md` for usage. No real DB import/rebuild has been run.

- [x] Verify that `split_meili_dump_by_port.add_port_hash()` recalculates the
  hash through the installed `nmap2json.smarthash.port_smart_hash`, even for
  already port-scoped documents.
- [x] Verify using synthetic SMTP reports and the updated library that date-only
  variants collapse to one UUID and one output JSON file, preserving raw dates.
- [x] Inspect `reimport_port_dump.py`: it keeps document IDs; a simple export
  followed by reimport does **not** recalculate hashes or fix these duplicates.
- [ ] Install/pin the corrected nmap2json version in the tools environment.
  Updating a separate source checkout does not update the installed package.
- [x] Implement timestamp merging in the migration tool: the legacy splitter's
  `write_time_companion()` currently
  overwrites an existing companion file for a merged UUID. Preserve the minimum
  `first_seen` and maximum `last_seen` over all source IDs, with regression tests
  for processing order and missing bounds. Reproduced on temporary files.
- [x] Select newest `body.endtime` (source last_seen fallback), deterministic
  serialized-payload tie-break, independently of traversal order in the migration.
- [ ] Validate a complete disposable export -> rehash/split -> replacement import
  round trip, including history, document counts and stale old-ID removal.
- [x] Enforce a fresh output directory: otherwise old hashed files remain alongside
  the new ones. Preserve source observation times from IN Kvrocks before any
  replacement, then use `.time` companions during reimport.
- [ ] Update/deploy scanners to use the same normalization before production
  recovery, so they do not continue introducing legacy hashes.

Expected recovery path: export -> migrate_smarthash with the corrected library and
timestamp merge -> replace the Meilisearch index and rebuild Kvrocks using the
new IDs and merged `.time` files. Plain incremental import leaves old IDs behind.
Only differences normalized by smarthash merge; meaningful content differences
must remain separate. Backups and production execution remain operator-managed.
