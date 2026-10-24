# Architecture

One process: FastAPI serves the API, the single `index.html`, and runs the checker as an asyncio task.

```
 Browser (index.html)                       Public viewer (/status/<slug>)
   |  fetch JSON (cookie session)              |  GET snapshot + EventSource
   v                                           v
+------------------------------------------------------------------+
|  FastAPI (app.py)                                                |
|   auth + rate limit | monitors | incidents | status | SSE stream  |
|        |                                          ^              |
|        v                                          | publish()    |
|   SQLite (pulse.db, WAL)  <---- record_check ---- worker loop    |
|                                                   |  tick 2s     |
|                                      due monitors -> probe()     |
+---------------------------------------------------|--------------+
                                                    v
                          check_url(): scheme + DNS + is_global
                          pin IP, send Host/SNI, re-check per redirect
                                                    v
                                              target website
```

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | /api/register | no (rate limited) | create user, start session |
| POST | /api/login | no (rate limited) | verify password, start session |
| POST | /api/logout | cookie | end session |
| GET | /api/me | cookie | current user + status page slug |
| GET | /api/monitors | cookie | monitors with 24h uptime, sparkline data, incident flag |
| POST | /api/monitors | cookie | add monitor `{name, url, interval_s}`; SSRF-checked |
| DELETE | /api/monitors/{id} | cookie | remove own monitor |
| GET | /api/incidents | cookie | last 50 incidents for own monitors |
| GET | /api/status/{slug} | no | public snapshot (names only, no URLs) |
| GET | /api/status/{slug}/stream | no | SSE, `event: check` per probe result |
| GET | / , /status/{slug} | no | serves index.html |

## DB schema (SQLite)

```sql
users(id PK, email UNIQUE, password_hash, slug UNIQUE, created_at)
sessions(token_hash PK, user_id FK, expires_at)          -- sha256 of the cookie token
monitors(id PK, user_id FK, name, url, interval_s, consecutive_failures, created_at)
checks(id PK, monitor_id FK, ts, ok, status_code, latency_ms, error)
  INDEX idx_checks_monitor_ts (monitor_id, ts)
incidents(id PK, monitor_id FK, started_at, ended_at NULL, reason)
  INDEX idx_incidents_monitor (monitor_id, ended_at)
```

All foreign keys are `ON DELETE CASCADE`. Timestamps are epoch seconds. Checks older than 7 days are pruned hourly.

## Incident rules

- `consecutive_failures` increments on a failed check and resets to 0 on success.
- At 3 and no open incident: insert an incident (`ended_at` NULL).
- Any success closes the open incident (`ended_at = now`).
