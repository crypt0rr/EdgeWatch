# Security policy

Please report security vulnerabilities privately through GitHub's security advisory feature for this repository. Do not open a public issue containing exploit details, credentials, notification URLs, or target information.

EdgeWatch executes Nmap with validated argument arrays and does not expose arbitrary Nmap flags. Treat its configuration, SQLite volume, notification URL file, and notification encryption key as sensitive. Only configure targets you own or are explicitly authorized to scan.

The administration console is bound to a loopback address by default and uses
server-side sessions, CSRF protection, and Argon2id password storage. Keep the
Docker host and any SSH tunnel access restricted to trusted administrators.

Web-managed Shoutrrr destinations are write-only through the API. Their URLs
are encrypted at rest with AES-256-GCM; the key is stored in
`./data/notification.key` unless `notifications.encryption_key_file` is
configured. Protect that key as a credential, keep it mode `0600`, and include
it in backups of the corresponding SQLite database. Do not report notification
URLs or key material in issues, logs, screenshots, or audit records.

If the key is lost or replaced, web-managed destinations become unavailable;
they cannot be recovered from the database alone. Restore the original key and
database together, or delete and recreate the affected destinations after
confirming that the old credentials are revoked. A database upgraded to schema
3 must not be opened by an older EdgeWatch binary; downgrade by restoring the
complete pre-upgrade `./data` backup before starting the old version.
