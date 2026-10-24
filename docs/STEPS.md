# Steps

1. Schema first: users, sessions, monitors, checks, incidents, plus the `(monitor_id, ts)` index that every dashboard query leans on.
2. Auth: argon2 hashes, random session tokens (only their sha256 is stored) in an httpOnly SameSite=Lax cookie, in-memory rate limit on register/login, CORS locked to localhost.
3. SSRF guard (`check_url`): http(s) only, no userinfo, resolve the host, every address must be `is_global`.
4. Prober: pin the vetted IP in the URL, keep the real `Host` header and SNI, follow redirects manually and re-validate each hop.
5. Worker: a 2s tick selects monitors whose last check is older than their interval, runs them concurrently (semaphore, in-flight set), records the result.
6. Incident bookkeeping inside the same transaction as the check insert: open at 3 consecutive failures, close on first success.
7. Fan-out: after each check, `publish()` pushes an event to per-slug queues; the SSE endpoint drains its queue and pings every 15s.
8. Frontend: one `index.html`; dashboard polls every 10s, public page renders a snapshot then merges SSE events. Seed script generates 24h of fake history using the same incident rule.

# Interview Q&A

**1. How do you defend against SSRF here?**
Allowlist the scheme (http/https), reject credentials in the URL, resolve the hostname, and require every returned address to be globally routable (`is_global` rejects private, loopback, link-local, CGNAT, reserved). IPv4-mapped IPv6 is unwrapped first so `::ffff:127.0.0.1` can't sneak by. Redirects are followed manually and each hop goes through the same check. In production I'd also add an egress firewall or a dedicated proxy, since app-level checks are one layer.

**2. What about DNS rebinding?**
Validating a hostname and then letting the HTTP client resolve it again is a time-of-check/time-of-use gap: the attacker's DNS can answer with a public IP the first time and 127.0.0.1 the second. So the prober connects to the vetted IP directly, sends the original `Host` header, and sets `sni_hostname` so TLS certificate verification still checks the real name.

**3. SSE or WebSockets for the live status page?**
Updates only flow server to client, so SSE fits: plain HTTP, automatic reconnect, works with the browser's `EventSource`, no upgrade handshake or framing code. WebSockets earn their keep when the client also sends frequent messages or you need binary. The tradeoff: SSE has a per-origin connection limit on HTTP/1.1 and no built-in replay, so the client reloads the snapshot after reconnecting.

**4. How is 24h uptime computed, and where is it wrong?**
`successful checks / total checks` in the last 24 hours. It's an approximation: it assumes evenly spaced checks, so a monitor with a 10s interval and one with a 1h interval aren't weighted by time. Gaps (server was off) count as nothing rather than downtime. A stricter version integrates up/down time over the window. For scale: 99.9% is about 86 seconds of downtime per day.

**5. How do you stop alert flapping?**
Opening an incident needs 3 consecutive failures, so one dropped packet does nothing. Closing is asymmetric: the first success closes it, which is simple but can flap if a service alternates fail/pass. The usual fix is hysteresis: require N consecutive successes to resolve, or a cooldown before reopening.

**6. Why an in-process asyncio task instead of Celery or cron?**
For a local MVP it's the least moving parts: a tick loop, a semaphore to bound concurrency, and an in-flight set so a slow target isn't double-scheduled. The limits: running several uvicorn workers would run several schedulers and duplicate checks, and a crash loses in-flight work. Past one box I'd split the checker into its own process with a real queue or leader lock.

**7. What are SQLite's limits for this workload?**
One writer at a time. WAL lets readers proceed during writes, and the busy timeout absorbs short contention, but the checks table is write-heavy (monitors x checks per day) and grows forever without pruning, hence the 7-day retention. It's a local file, so no network access and no horizontal scaling. When writes or users outgrow it, move to Postgres, and the queries mostly carry over.

**8. Why cookie sessions over JWT, and what does the rate limit not cover?**
Server-side sessions can be revoked instantly (logout deletes the row) and the httpOnly cookie is invisible to page JavaScript, which limits XSS damage; SameSite=Lax plus JSON-only bodies and locked CORS covers CSRF here. Only a hash of the token is stored, so a DB leak doesn't leak live sessions. The rate limiter is per-IP and in memory: it resets on restart, doesn't share across processes, and can be sidestepped with many IPs. The 409 on duplicate registration also reveals which emails exist.
