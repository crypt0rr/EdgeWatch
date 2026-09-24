# Scan history API compatibility

The authenticated historical scan endpoints have two response shapes:

| Endpoint | Response | Use |
| --- | --- | --- |
| `GET /api/v1/scans/{scanID}/summary` | Scan metadata only | Scan history/detail headers and status displays. Does not read or return stored results. |
| `GET /api/v1/scans/{scanID}` | Full scan, including `snapshot` and `changes` | Existing API clients that need the complete historical result. |
| `GET /api/v1/scans/{scanID}/hosts` | Paginated effective-host summaries | Host inventory and per-address navigation. |

The original full-response endpoint is retained for compatibility. New clients
that only need scan metadata should use `/summary`, then request paginated
results or host evidence separately when needed. This avoids loading large
snapshots just to show scan status and timestamps.
