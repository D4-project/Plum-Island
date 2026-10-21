# Reports

Plum Island generates reports from the structured Kvrocks query syntax used by
the search UI. Reports can be previewed, downloaded as PDF, or emailed manually
and on a weekly/monthly schedule. Emails contain a short summary and the complete
report as a PDF attachment.

## Report configuration

A report contains:

- a name and description
- a structured search query
- one or more recipient email addresses
- a monthly or weekly schedule
- a `Report active` flag

`Report active` only controls automatic scheduled delivery.
Preview and manual `Run now` actions remain available for inactive reports.
Enter recipients one per line or separated by commas; duplicate addresses are
removed when saving.

### First report

1. Configure SMTP in `webapp/config.py` using the settings below, then restart
   the application and any separately managed scheduler process.
2. Create a report with a descriptive name, a query, recipients and a schedule.
   Leave `Report active` disabled while checking the content.
3. Use `Preview` to check the matching hosts and period, then download the PDF
   to verify the complete report. Preview does not send mail.
4. Use `Run now` to send a real email to the configured recipients. Check the
   short body and PDF attachment before enabling automatic delivery.

Use an account authorized for the corresponding Reports actions. Preview,
download and send routes retain Flask-AppBuilder access controls.

### Search query

Use the [structured search syntax](search.md), for example:

```text
net:193.168.1.0/24 or domain_requested:example.org
```

Queries are validated when adding or editing reports using the existing search
parser and shared tag validator. Validation does not execute a backend search
or guarantee that the query will match data; use Preview to check the result.

Choose domain fields carefully:

- `domain_requested:example.org` selects the domain explicitly requested for
  scanning, derived from hostname entries of type `user`.
- `domain:example.org` also matches domains discovered in scan content, such as
  an HTTP redirect or a certificate. It does not imply that domain was the target.

Separate alternatives with `OR`; terms within a group use implicit `AND`.
One level of parentheses can share filters across alternatives, for example
`(domain_requested:example.org OR net:192.0.2.0/24) tag:lang:php`.
Nested groups and `NOT (group)` are rejected on save. Validation uses the same
compiler as search; it does not contact search backends.
Always prefix an IP or network with its keyword, including IPv6
(`net:2001:db8::/48` is a syntax example, not a public scan target).

## Report interval

Report queries are always executed inside a reporting interval.

For monthly reports, interval is one calendar month ending at run time.
For weekly reports, interval is seven days ending at run time.

For monthly schedules, `Day` is day of month (`1`–`28`). For weekly
schedules, it is weekday (`1` = Monday through `7` = Sunday).
`Hour UTC` is the scheduled hour in UTC, not local time; it does not shift with
daylight-saving time.

Reports never use `last_run_at` to choose their content. Preview, manual run,
and scheduled run therefore produce same period at same run time. `last_run_at`
records delivery only.

After a successful manual or scheduled send, Plum updates `Last report` and
recalculates `Next automatic report`. A manual send therefore also updates the
next scheduled execution. Preview changes neither delivery timestamp.
If a scheduled run is late, its interval still ends at actual run time, not at
the originally scheduled date.

Monthly comparison uses preceding calendar month. Weekly comparison uses
preceding seven days.

The query is the business filter. The report interval is the time filter imposed by reporting.

## Markdown content

Reports are generated as Markdown.

The full report (preview and attached PDF) contains:

- top-level `Report for <name>.` heading
- report summary metadata
- query and reporting period
- number of matching IPs and scan results
- open port summary, showing total hosts exposing each port during the report period
- `New opened port`, explaining and grouping ports newly observed against the preceding equivalent period under bold port labels with numerically sorted affected IPv4/IPv6 sub-bullets; IPs link to their matching Full report dump host
- non-empty `FQDN detected` and `FQDN discovered in Passive DNS` lists, each sorted by domain; both list affected IPs linked to their matching Full report dump host. Detected FQDNs include hostnames from any scan result field, including certificate records; Passive DNS keeps records active within the previous 90 days and shows the latest observation
- full report dump sorted by numeric IP order
- per-host tags when present
- redundant `vendor:<name>` tags are omitted when matching `product:<name>` exists
- the report-specific `domain:circl.lu` tag is omitted from host display
- per-host open ports
- per-host associated FQDNs from PTR records seen in the last 6 months, then `fqdn_requested`, completed with Passive DNS `A` records up to 25 entries
- non-empty protocol host views: `Webservices related host` for HTTP/HTTPS, `Mail related` for SMTP/IMAP/POP3, `Remote access` for VPN/SSH/Telnet/RDP, and `Other` for hosts without those tags
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

The `Preview` action generates the canonical Markdown report without sending email,
then renders its safe HTML subset. Preview offers an index linked to stable heading
anchors, print action, and a PDF download once generation is complete. The PDF uses
a cover page with the report name, a linked index on page two, starts every level-two
report section on a new page, and preserves internal IP links to the Full report dump. HTML escaping is
applied to all report values; host tags render as simple HTML
`code` tags without custom CSS. The index follows the report title and summary
metadata.
Because Passive DNS enrichment can be slow, preview first opens a progress modal and only redirects to the rendered report when generation is complete.

The modal follows the report generation order:

- `Generating report`
- `Comparing with previous report`
- `Resolving Passive DNS X/XX`

## Email delivery

SMTP delivery is controlled by the `REPORT_SMTP_*` settings in `webapp/config.py`.
The bundled [configuration template](../webapp/config.py.template) lists the
settings; changing the template alone does not change a running installation.
Restart the application and any separately managed scheduler after changing
`webapp/config.py`.
For Docker, environment variables named `REPORT_SMTP_*` alone are not consumed:
follow the [persistent mounted configuration procedure](installation.md#persistent-custom-configuration-including-report-smtp).
The mounted file must contain the full application configuration, including the
persistent SQLite path. See also the [scheduler startup limitations](installation.md#scheduler-startup-and-production-limitations).

### SMTP settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `REPORT_SMTP_HOST` | `""` | Relay hostname. Empty disables scheduled sending; manual sending returns an error. |
| `REPORT_SMTP_PORT` | `25` | Relay port; set explicitly for the chosen transport. |
| `REPORT_SMTP_FROM` | `""` | Sender address displayed in the email's `From` header. |
| `REPORT_SMTP_USER` | `""` | Authentication username. Empty skips SMTP login. |
| `REPORT_SMTP_PASSWORD` | `""` | Password used when a username is configured. |
| `REPORT_SMTP_USE_TLS` | `False` | Upgrade the SMTP connection using STARTTLS. |
| `REPORT_SMTP_USE_SSL` | `False` | Use implicit TLS from connection establishment. |

Set the sender explicitly, for example:

```python
REPORT_SMTP_FROM = "plum@example.org"
```

Sender selection is `REPORT_SMTP_FROM`, then `REPORT_SMTP_USER` if From is
empty, then `plum-reports@localhost` if both are empty. A login name is not
necessarily an email address: configure a sender accepted by your relay instead
of relying on that fallback. Recipients come from each report, not this setting.

Example authenticated relay with STARTTLS:

```python
REPORT_SMTP_HOST = "smtp.example.org"
REPORT_SMTP_PORT = 587
REPORT_SMTP_FROM = "plum@example.org"
REPORT_SMTP_USER = "plum@example.org"
REPORT_SMTP_PASSWORD = "REPLACE_WITH_RELAY_PASSWORD"
REPORT_SMTP_USE_TLS = True
REPORT_SMTP_USE_SSL = False
```

For an implicit-TLS relay, use its port (commonly `465`), set
`REPORT_SMTP_USE_SSL = True` and `REPORT_SMTP_USE_TLS = False`.
For a trusted internal relay without login, leave user/password empty and use
the transport settings required by that relay. Ports do not select TLS
automatically. If both flags are true, implicit TLS takes precedence.
Keep real credentials out of version control.

### Message and attachment

The subject is `P.L.U.M. report: <report name>`. All configured recipients appear
in the `To` header; this is not a separate private message per recipient.
Manual and scheduled deliveries attach the complete report as a PDF, preserving
its cover, linked index, section page breaks and clickable host links.
The email body contains only the report title, query, period, matching IP/scan
counts, Open ports summary and disclaimer, plus a note pointing to the attachment.
The short body is provided as both Markdown plain text and safe rendered HTML,
without an index. The full report is not repeated in the email body.
PDF generation must succeed before SMTP delivery starts; a generation or delivery
failure does not mark the report as delivered. SMTP relays must allow attachments
large enough for the full PDF.

Successful sending means that the SMTP call completed, not that final mailbox
delivery has been confirmed. Check relay logs or bounces when a message is missing.

## Troubleshooting

- **No automatic email:** check `Report active`, `Next automatic report`, the UTC
  schedule, the running scheduler and a non-empty `REPORT_SMTP_HOST`.
- **`REPORT_SMTP_HOST is not configured`:** add the relay to the live
  `webapp/config.py` and restart the processes loading that configuration.
- **Wrong From address:** set `REPORT_SMTP_FROM` explicitly and restart; otherwise
  the username/default fallback above applies.
- **SMTP login, TLS or sender rejection:** verify the relay's hostname, port,
  transport flags, credentials and permitted sender address.
- **Generation or send failure:** inspect application logs for
  `Scheduled report <id> failed` or `Manual report <id> failed`. Delivery timestamps
  are not advanced on exceptions. A scheduled report remains due and can be retried
  by a later scheduler invocation.
- **Preview works but sending fails:** preview does not test SMTP; check PDF
  generation and relay attachment-size limits as well.
- **Unexpected hosts:** check the entire query, especially OR branches and the
  distinction between `domain` and `domain_requested` described above.
- **Slow preview:** Passive DNS enrichment can take time. Follow the progress
  modal; do not assume that an unfinished preview has sent an email.

## PTR hostname window

`REPORT_PTR_LAST_SEEN_MONTHS` controls how recent a source document must be for its PTR hostname to appear in a report.
The default is 6 months before the report end time.

Passive DNS enrichment separately requires both `PASSIVE_USER` and `PASSIVE_PWD`
in `webapp/config.py`. If either is empty, enrichment is skipped; the report can
still be generated from indexed scan data. This does not change the PTR window
or the 90-day cutoff used for the Passive DNS discovery list.
