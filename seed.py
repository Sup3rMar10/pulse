"""Fake monitors plus a day of fake history. Safe to re-run: it recreates the demo user."""
import random
import time

from app import db, hasher, init_db

DEMO_EMAIL, DEMO_PASSWORD, DEMO_SLUG = "demo@example.com", "demo-password-123", "demo"
STEP = 300  # one seeded check every 5 minutes

# name, url, typical latency ms, outages as (hours ago it started, minutes it lasted)
# a 5-minute outage is a single failed check: a blip that must NOT open an incident
MONITORS = [
    ("Marketing site", "https://example.com/", 120, [(15, 25)]),
    ("Public API", "https://example.org/", 230, [(6, 40), (20, 15)]),
    ("Docs", "https://example.net/", 90, [(9, 5)]),
    ("Checkout", "https://www.iana.org/", 310, [(2, 20)]),
]


def seed():
    random.seed(42)
    init_db()
    now = int(time.time())
    with db() as c:
        c.execute("DELETE FROM users WHERE email=?", (DEMO_EMAIL,))
        uid = c.execute("INSERT INTO users(email,password_hash,slug,created_at) VALUES (?,?,?,?)",
                        (DEMO_EMAIL, hasher.hash(DEMO_PASSWORD), DEMO_SLUG, now - 86400)).lastrowid
        for name, url, base, outages in MONITORS:
            mid = c.execute("INSERT INTO monitors(user_id,name,url,interval_s,created_at) VALUES (?,?,?,?,?)",
                            (uid, name, url, 30, now - 86400)).lastrowid
            windows = [(now - h * 3600, now - h * 3600 + m * 60) for h, m in outages]
            fails, inc = 0, None
            for k in range(86400 // STEP):
                ts = now - 86400 + k * STEP
                down = any(a <= ts < b for a, b in windows)
                ms = None if down else max(20, int(random.gauss(base, base * 0.15)))
                c.execute("INSERT INTO checks(monitor_id,ts,ok,status_code,latency_ms,error) VALUES (?,?,?,?,?,?)",
                          (mid, ts, int(not down), 503 if down else 200, ms, None))
                if down:
                    fails += 1
                    if fails == 3:  # same rule as the live worker
                        inc = c.execute("INSERT INTO incidents(monitor_id,started_at,reason) VALUES (?,?,?)",
                                        (mid, ts, "HTTP 503")).lastrowid
                else:
                    if inc:
                        c.execute("UPDATE incidents SET ended_at=? WHERE id=?", (ts, inc))
                    fails, inc = 0, None
    print(f"seeded. login: {DEMO_EMAIL} / {DEMO_PASSWORD}  public page: /status/{DEMO_SLUG}")


if __name__ == "__main__":
    seed()
