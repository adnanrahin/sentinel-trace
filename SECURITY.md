# Security

Report vulnerabilities privately to the repository owners. Do not open a public issue with a real secret attached.

sentinal-trace:

- never validates credentials by using them
- never executes scanned content
- never stores raw secrets in the default audit database

If you believe output, logs, or `audit.db` contained a live secret, rotate that credential and file a report.
