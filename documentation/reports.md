# Reports

Plum Island can generate scheduled Markdown reports from the same structured Kvrocks query syntax used by the search UI.

## Report configuration

A report contains:

- a name and description
- a structured search query
- one or more recipient email addresses
- a monthly or weekly schedule
- a `Report active` flag

`Report active` only controls automatic scheduled delivery.
Preview and manual `Run now` actions remain available for inactive reports.

## Report interval

Report queries are always executed inside a reporting interval.

For monthly reports, interval is one calendar month ending at run time.
For weekly reports, interval is seven days ending at run time.

For monthly schedules, `Day` is day of month (`1`–`28`). For weekly
schedules, it is weekday (`1` = Monday through `7` = Sunday).

Reports never use `last_run_at` to choose their content. Preview, manual run,
and scheduled run therefore produce same period at same run time. `last_run_at`
records delivery only.

Monthly comparison uses preceding calendar month. Weekly comparison uses
preceding seven days.

The query is the business filter. The report interval is the time filter imposed by reporting.

## Markdown content

Reports are generated as Markdown.

The current report body contains:

- report summary
- query and reporting period
- number of matching IPs and scan results
- open port summary
- `New opened port`, comparing the current period with preceding period
- non-empty `FQDN detected` and `Passive DNS FQDN detected` lists, each sorted by domain; the first excludes Passive DNS entries
- host list sorted by numeric IP order
- per-host tags when present
- per-host open ports
- per-host associated FQDNs from PTR records seen in the last 6 months, then `fqdn_requested`, completed with Passive DNS `A` records up to 25 entries
- non-empty protocol host views: `Web hosts` (`proto:http` or `proto:https`), `Mail related` (`proto:smtp`, `proto:imap`, or `proto:pop3`), and `Other` for hosts without those tags
- Passive DNS FQDNs include their CIRCL `time_last` observation timestamp, or `N/A` when unavailable
- an as-is disclaimer

Example host entry:

```md
- 158.64.1.27
  - Tag: vuln:filelisting
  - Open ports: 443
  - Associated FQDNs (3)
    - reverse.example.org (ptr)
    - scan-request.example.org
    - historical.example.org (pdns) — last seen: 2026-09-16 12:00:00 UTC
```

## Preview generation

The `Preview` action generates the Markdown report without sending email.
Because Passive DNS enrichment can be slow, preview first opens a progress modal and only redirects to the rendered report when generation is complete.

The modal follows the report generation order:

- `Generating report`
- `Comparing with previous report`
- `Resolving Passive DNS X/XX`

## Email delivery

SMTP delivery is controlled by the `REPORT_SMTP_*` settings in `webapp/config.py`.
If `REPORT_SMTP_HOST` is empty, automatic report delivery is disabled.

`REPORT_PTR_LAST_SEEN_MONTHS` controls how recent a source document must be for its PTR hostname to appear in a report.
The default is 6 months before the report end time.
