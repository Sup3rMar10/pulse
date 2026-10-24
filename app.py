"""Pulse: uptime monitor. FastAPI + SQLite, one process, one background task."""
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import socket
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

log = logging.getLogger("pulse")

DB_PATH = Path(__file__).with_name("pulse.db")
INDEX = Path(__file__).with_name("index.html")

TICK_S = 2                  # scheduler wake-up
PROBE_TIMEOUT_S = 10
MAX_REDIRECTS = 3
MAX_CONCURRENT = 20
FAIL_THRESHOLD = 3          # consecutive failures before an incident opens
RETENTION_S = 7 * 86400
SESSION_TTL_S = 7 * 86400
MAX_MONITORS = 20
MAX_SUBSCRIBERS = 200
UA = "pulse-monitor/1.0"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG_RE = re.compile(r"^[a-z0-9-]{3,32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS monitors(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  interval_s INTEGER NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS checks(
  id INTEGER PRIMARY KEY,
  monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  status_code INTEGER,
  latency_ms INTEGER,
  error TEXT);
CREATE INDEX IF NOT EXISTS idx_checks_monitor_ts ON checks(monitor_id, ts);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY,
  monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  reason TEXT);
CREATE INDEX IF NOT EXISTS idx_incidents_monitor ON incidents(monitor_id, ended_at);
"""

hasher = PasswordHasher()
DUMMY_HASH = hasher.hash("not-a-real-password")  # keeps login timing flat for unknown emails


# ---------- db ----------

@contextmanager
def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init_db():
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------- SSRF guard ----------

def resolve_public(host: str) -> str:
    """Resolve host and return one IP, refusing anything that isn't a public address."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("could not resolve host")
    ips = sorted({i[4][0].split("%")[0] for i in infos})
    if not ips:
        raise ValueError("could not resolve host")
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise ValueError("private, loopback and link-local addresses are blocked")
    return ips[0]


def check_url(url: str) -> str:
    """Validate scheme/shape and return a vetted IP for the host."""
    if not url.isascii() or re.search(r"\s", url):
        raise ValueError("URL must be plain ASCII without whitespace")
    p = urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("only http and https URLs are allowed")
    if not p.hostname:
        raise ValueError("URL has no host")
    if p.username or p.password:
        raise ValueError("credentials in URLs are not allowed")
    p.port  # raises ValueError on a bad port
    return resolve_public(p.hostname)


# ---------- probing ----------

async def probe(client: httpx.AsyncClient, url: str):
    """GET url, re-validating and pinning the IP on every hop. Returns (ok, code, ms, error)."""
    t0 = time.perf_counter()
    try:
        for _ in range(MAX_REDIRECTS + 1):
            p = urlsplit(url)
            ip = await asyncio.to_thread(check_url, url)
            host = f"[{ip}]" if ":" in ip else ip
            port = f":{p.port}" if p.port else ""
            target = f"{p.scheme}://{host}{port}{p.path or '/'}" + (f"?{p.query}" if p.query else "")
            ext = {"sni_hostname": p.hostname} if p.scheme == "https" else {}
            async with client.stream("GET", target, headers={"Host": p.netloc, "User-Agent": UA},
                                     extensions=ext) as r:
                code, loc = r.status_code, r.headers.get("location")
            if 300 <= code < 400 and loc:
                url = urljoin(url, loc)
                continue
            ms = int((time.perf_counter() - t0) * 1000)
            return code < 400, code, ms, None
        raise ValueError("too many redirects")
    except (httpx.HTTPError, ValueError, OSError) as e:
        return False, None, None, f"{type(e).__name__}: {e}"[:200]


# ---------- live updates (SSE fan-out) ----------

subs: dict[str, set] = defaultdict(set)


def publish(slug: str, event: dict):
    for q in list(subs[slug]):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass  # slow reader: it will resync on reconnect


# ---------- check bookkeeping ----------

def uptime_24h(c, mid: int, now: int):
    r = c.execute("SELECT COUNT(*) n, SUM(ok) up FROM checks WHERE monitor_id=? AND ts>=?",
                  (mid, now - 86400)).fetchone()
    return round(100.0 * r["up"] / r["n"], 2) if r["n"] else None


def incident_open(c, mid: int) -> bool:
    return c.execute("SELECT 1 FROM incidents WHERE monitor_id=? AND ended_at IS NULL",
                     (mid,)).fetchone() is not None


def record_check(mid, ok, code, ms, err):
    now = int(time.time())
    with db() as c:
        m = c.execute("SELECT m.name, m.consecutive_failures f, u.slug FROM monitors m "
                      "JOIN users u ON u.id=m.user_id WHERE m.id=?", (mid,)).fetchone()
        if not m:
            return None  # deleted while the probe was in flight
        c.execute("INSERT INTO checks(monitor_id,ts,ok,status_code,latency_ms,error) VALUES (?,?,?,?,?,?)",
                  (mid, now, int(ok), code, ms, err))
        fails = 0 if ok else m["f"] + 1
        c.execute("UPDATE monitors SET consecutive_failures=? WHERE id=?", (fails, mid))
        if ok:
            c.execute("UPDATE incidents SET ended_at=? WHERE monitor_id=? AND ended_at IS NULL", (now, mid))
        elif fails >= FAIL_THRESHOLD and not incident_open(c, mid):
            c.execute("INSERT INTO incidents(monitor_id,started_at,reason) VALUES (?,?,?)",
                      (mid, now, err or f"HTTP {code}"))
        return {"slug": m["slug"], "id": mid, "name": m["name"], "ok": bool(ok), "status_code": code,
                "latency_ms": ms, "ts": now, "uptime_24h": uptime_24h(c, mid, now),
                "incident_open": incident_open(c, mid)}


def due_monitors():
    now = int(time.time())
    with db() as c:
        rows = c.execute("SELECT m.id, m.url, m.interval_s, "
                         "(SELECT MAX(ts) FROM checks WHERE monitor_id=m.id) last FROM monitors m").fetchall()
    return [dict(r) for r in rows if r["last"] is None or r["last"] + r["interval_s"] <= now]


def prune():
    with db() as c:
        c.execute("DELETE FROM checks WHERE ts<?", (int(time.time()) - RETENTION_S,))
        c.execute("DELETE FROM sessions WHERE expires_at<?", (int(time.time()),))


async def run_one(m, client, sem, inflight):
    try:
        async with sem:
            ok, code, ms, err = await probe(client, m["url"])
        ev = await asyncio.to_thread(record_check, m["id"], ok, code, ms, err)
        if ev:
            publish(ev.pop("slug"), ev)
    except Exception:
        log.exception("check failed for monitor %s", m["id"])
    finally:
        inflight.discard(m["id"])


async def worker(client):
    sem, inflight, tasks, last_prune = asyncio.Semaphore(MAX_CONCURRENT), set(), set(), 0.0
    while True:
        try:
            for m in await asyncio.to_thread(due_monitors):
                if m["id"] in inflight:
                    continue
                inflight.add(m["id"])
                t = asyncio.create_task(run_one(m, client, sem, inflight))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
            if time.monotonic() - last_prune > 3600:
                await asyncio.to_thread(prune)
                last_prune = time.monotonic()
        except Exception:
            log.exception("scheduler tick failed")
        await asyncio.sleep(TICK_S)


@asynccontextmanager
async def lifespan(_app):
    init_db()
    client = httpx.AsyncClient(timeout=httpx.Timeout(PROBE_TIMEOUT_S), follow_redirects=False)
    task = asyncio.create_task(worker(client))
    yield
    task.cancel()
    await client.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


# ---------- auth ----------

class Creds(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)


class MonitorIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    url: str = Field(max_length=2048)
    interval_s: int = Field(30, ge=10, le=3600)


HITS: dict[str, deque] = defaultdict(deque)


def auth_limit(request: Request):
    """10 auth attempts per minute per IP, in memory."""
    ip = request.client.host if request.client else "?"
    q, now = HITS[ip], time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 10:
        raise HTTPException(429, "too many attempts, slow down")
    q.append(now)


def start_session(response: Response, uid: int):
    tok = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES (?,?,?)",
                  (sha(tok), uid, int(time.time()) + SESSION_TTL_S))
    response.set_cookie("pulse_session", tok, max_age=SESSION_TTL_S, httponly=True, samesite="lax")


def current_user(pulse_session: str | None = Cookie(None)):
    if not pulse_session:
        raise HTTPException(401, "not signed in")
    with db() as c:
        row = c.execute("SELECT u.id, u.email, u.slug FROM sessions s JOIN users u ON u.id=s.user_id "
                        "WHERE s.token_hash=? AND s.expires_at>?",
                        (sha(pulse_session), int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, "not signed in")
    return dict(row)


@app.post("/api/register", status_code=201)
def register(body: Creds, response: Response, _=Depends(auth_limit)):
    email = body.email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise HTTPException(422, "invalid email")
    slug = secrets.token_hex(4)
    try:
        with db() as c:
            uid = c.execute("INSERT INTO users(email,password_hash,slug,created_at) VALUES (?,?,?,?)",
                            (email, hasher.hash(body.password), slug, int(time.time()))).lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "email already registered")
    start_session(response, uid)
    return {"email": email, "slug": slug}


@app.post("/api/login")
def login(body: Creds, response: Response, _=Depends(auth_limit)):
    email = body.email.strip().lower()
    with db() as c:
        row = c.execute("SELECT id, email, slug, password_hash FROM users WHERE email=?", (email,)).fetchone()
    ok = False
    try:
        hasher.verify(row["password_hash"] if row else DUMMY_HASH, body.password)
        ok = row is not None
    except VerificationError:
        pass
    if not ok:
        raise HTTPException(401, "invalid credentials")
    start_session(response, row["id"])
    return {"email": row["email"], "slug": row["slug"]}


@app.post("/api/logout", status_code=204)
def logout(response: Response, pulse_session: str | None = Cookie(None)):
    if pulse_session:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (sha(pulse_session),))
    response.delete_cookie("pulse_session")


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"email": user["email"], "slug": user["slug"]}


# ---------- monitors ----------

def monitor_view(c, m, public=False):
    now = int(time.time())
    last = c.execute("SELECT ok, status_code, latency_ms, ts FROM checks WHERE monitor_id=? "
                     "ORDER BY ts DESC LIMIT 1", (m["id"],)).fetchone()
    recent = c.execute("SELECT ok, latency_ms FROM checks WHERE monitor_id=? ORDER BY ts DESC LIMIT 40",
                       (m["id"],)).fetchall()
    v = {"id": m["id"], "name": m["name"],
         "ok": bool(last["ok"]) if last else None,
         "status_code": last["status_code"] if last else None,
         "latency_ms": last["latency_ms"] if last else None,
         "ts": last["ts"] if last else None,
         "uptime_24h": uptime_24h(c, m["id"], now),
         "spark": [r["latency_ms"] if r["ok"] else None for r in reversed(recent)],
         "incident_open": incident_open(c, m["id"])}
    if not public:
        v["url"], v["interval_s"] = m["url"], m["interval_s"]
    return v


@app.get("/api/monitors")
def list_monitors(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM monitors WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
        return [monitor_view(c, m) for m in rows]


@app.post("/api/monitors", status_code=201)
def add_monitor(body: MonitorIn, user=Depends(current_user)):
    url, name = body.url.strip(), body.name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    try:
        check_url(url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as c:
        n = c.execute("SELECT COUNT(*) FROM monitors WHERE user_id=?", (user["id"],)).fetchone()[0]
        if n >= MAX_MONITORS:
            raise HTTPException(400, f"limit of {MAX_MONITORS} monitors reached")
        mid = c.execute("INSERT INTO monitors(user_id,name,url,interval_s,created_at) VALUES (?,?,?,?,?)",
                        (user["id"], name, url, body.interval_s, int(time.time()))).lastrowid
    return {"id": mid}


@app.delete("/api/monitors/{mid}", status_code=204)
def delete_monitor(mid: int, user=Depends(current_user)):
    with db() as c:
        if c.execute("DELETE FROM monitors WHERE id=? AND user_id=?", (mid, user["id"])).rowcount == 0:
            raise HTTPException(404, "not found")


@app.get("/api/incidents")
def list_incidents(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT i.id, m.name, i.started_at, i.ended_at, i.reason FROM incidents i "
                         "JOIN monitors m ON m.id=i.monitor_id WHERE m.user_id=? "
                         "ORDER BY i.started_at DESC LIMIT 50", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


# ---------- public status page ----------

def owner(c, slug: str):
    u = c.execute("SELECT id FROM users WHERE slug=?", (slug,)).fetchone() if SLUG_RE.fullmatch(slug) else None
    if not u:
        raise HTTPException(404, "no such status page")
    return u


@app.get("/api/status/{slug}")
def public_status(slug: str):
    with db() as c:
        u = owner(c, slug)
        mons = c.execute("SELECT * FROM monitors WHERE user_id=? ORDER BY id", (u["id"],)).fetchall()
        inc = c.execute("SELECT m.name, i.started_at, i.ended_at FROM incidents i "
                        "JOIN monitors m ON m.id=i.monitor_id WHERE m.user_id=? "
                        "ORDER BY i.started_at DESC LIMIT 10", (u["id"],)).fetchall()
        return {"monitors": [monitor_view(c, m, public=True) for m in mons],
                "incidents": [dict(r) for r in inc]}


def check_slug(slug: str):
    with db() as c:
        owner(c, slug)


@app.get("/api/status/{slug}/stream")
async def status_stream(slug: str):
    await asyncio.to_thread(check_slug, slug)
    if sum(len(s) for s in subs.values()) >= MAX_SUBSCRIBERS:
        raise HTTPException(503, "too many live viewers")
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subs[slug].add(q)

    async def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                    yield f"event: check\ndata: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"  # keeps proxies and idle timers happy
        finally:
            subs[slug].discard(q)
            if not subs[slug]:
                subs.pop(slug, None)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------- pages ----------

@app.get("/")
def home():
    return FileResponse(INDEX)


@app.get("/status/{slug}")
def status_page(slug: str):
    return FileResponse(INDEX)
