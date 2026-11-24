#!/usr/bin/env python3
"""Watch www.qipu.org from outside: pages, data, the assistant, the alert links, tiles, the data site,
DNS, certificates and the server's own numbers. Push to a phone (ntfy) and mail (Resend) when
something breaks, once, then when it is fixed; a short summary once a day.

Runs on GitHub's runners (ops/monitor/workflow.yml), never on the site's server or the work machine,
so it still speaks when either is down. Standard library only; read-only and polite: about 25
requests a run, one at a time, no load.

    python3 site_monitor.py                 # check, print, notify on changes (state file below)
    python3 site_monitor.py --summary       # the same plus the slower checks and the daily summary
    python3 site_monitor.py --dry-run       # check and print only: no notification, no state written
    python3 site_monitor.py --origin <server address> --insecure-origin --dry-run
                                            # ask the server directly, as www.qipu.org (before the move,
                                            # or to see the origin behind Cloudflare)

Settings (environment; secrets come from GitHub secrets, never from the repo):
  BASE_URL              the site                                         [https://www.qipu.org]
  ORIGIN_IP             also ask the server directly at this address, with the site's name
  ORIGIN_INSECURE       1: accept the server's certificate without checking it (self-signed)
  OPS_STATUS_TOKEN      the token of the server's /__ops/status (env/ops.env on the server)
  ALERTS_SECRET         the site's alert-link secret: check a signed link is accepted (nothing is sent)
  DNS_EXPECT            name=value,... each name must resolve to (or through) value, e.g.
                        www.qipu.org=<server address>   (unset: the names must just resolve)
  NTFY_TOPIC, NTFY_SERVER [https://ntfy.sh], NTFY_TOKEN   push to the phone
  RESEND_API_KEY, MAIL_TO, MAIL_FROM                      mail on breakage, recovery, summary
  HEARTBEAT_URL         pinged at the end of every run (healthchecks.io: tells you if this stops)
  STATE_FILE            what the last runs saw                           [monitor-state.json]
  REMIND_HOURS          repeat a still-broken alert after this long      [6]
  LOG_DETAIL            0: the log names what fails but prints no detail (public run logs)  [1]
  ASK_LIVE              1: --summary also asks the assistant one real question (one model call)  [1]
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

UA = "qipu-site-monitor/1.0"
OK, WARN, FAIL = "ok", "warn", "fail"
RANK = {OK: 0, WARN: 1, FAIL: 2}

# ── what is checked ─────────────────────────────────────────────────────────────────────────
# path, expected status, text the body must hold (None: none), at least this many money amounts.
# The same pages as the kit's healthcheck.sh and scripts/ops/post_deploy_check.py: a page whose data
# did not load shows its headings but no amounts.
PAGES = [
    ("/robots.txt", 200, "Sitemap:", 0),
    ("/sitemap.xml", 200, "<sitemapindex", 0),
    ("/", 307, None, 0),
    ("/fr", 200, 'lang="fr"', 10),
    ("/fr/france/paris/budget", 200, "€", 50),
    ("/en/usa/san-francisco", 200, "$", 20),
    ("/en/usa/san-francisco/the-city", 200, 'lang="en"', 0),   # the map page
    ("/en/canada/vancouver", 200, "$", 20),
    ("/pt/brasil/recife", 200, "R$", 5),
    ("/fr/france/draguignan", 200, "€", 5),                         # reads the R2 bucket
    ("/api/search-communes?q=drag", 200, "draguignan", 0),
]
DATA_FILES = ["/data/budget_index.json", "/data/us/sf/city/manifest.json"]
TILE_INDEX = "https://tiles.qipu.org/us/sf/city/r20261001/render/index.json"
TILE = "https://tiles.qipu.org/us/sf/city/r20261001/render/0/0/0.webp"
DATA_SITE = ("https://data.qipu.org/", "qipu data")
DNS_NAMES = ["www.qipu.org", "qipu.org", "tiles.qipu.org", "data.qipu.org"]
ASK_QUESTION = "Quelle est la dette de la Ville par habitant ?"   # scope paris, French
VERIF_EMAIL = "verification-des-liens@alertes.invalid"            # lib/alertes/verif-secret.ts

SLOW_MS, VERY_SLOW_MS = 4000, 20000      # a page slower than this: warn, fail
TLS_WARN_DAYS, TLS_FAIL_DAYS = 21, 7
DISK_WARN, DISK_FAIL = 85.0, 93.0        # % used
MEM_WARN, MEM_FAIL = 12.0, 5.0           # % available
LOAD_WARN, LOAD_FAIL = 2.0, 4.0          # load1 per CPU
STATUS_STALE_S = 300

AMOUNT = re.compile(r"\d[\d   ,.]*\s?(?:Md|M|k)?\s?€|(?:R\$|\$|€)\s?\d")


@dataclass
class Result:
    name: str
    level: str
    detail: str
    ms: int | None = None
    target: str = "site"


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    ms: int
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


# ── HTTP: one connection per request, any address, the site's name on top ──────────────────
def fetch(url: str, *, method: str = "GET", headers: dict | None = None, body: bytes | None = None,
          connect_ip: str | None = None, insecure: bool = False, timeout: float = 30) -> Response:
    """No redirect is followed. With connect_ip, the TCP connection goes there while the TLS name
    and the Host header stay the URL's (what `curl --resolve` does)."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    hdrs = {"User-Agent": UA, "Accept-Encoding": "gzip", "Host": host, **(headers or {})}
    t0 = time.monotonic()
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(connect_ip or host, port, timeout=timeout, context=ctx)
            if connect_ip:
                # keep SNI and certificate checks on the site's name while connecting to the address
                def _connect(c=conn):
                    sock = socket.create_connection((connect_ip, port), timeout)
                    c.sock = ctx.wrap_socket(sock, server_hostname=host)
                conn.connect = _connect
        else:
            conn = http.client.HTTPConnection(connect_ip or host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=hdrs)
        res = conn.getresponse()
        raw = res.read()
        enc = (res.getheader("content-encoding") or "").lower()
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            raw = zlib.decompress(raw)
        out = Response(res.status, {k.lower(): v for k, v in res.getheaders()}, raw, int((time.monotonic() - t0) * 1000))
        conn.close()
        return out
    except (OSError, http.client.HTTPException, ssl.SSLError, EOFError, zlib.error) as e:
        return Response(0, {}, b"", int((time.monotonic() - t0) * 1000), f"{type(e).__name__}: {e}"[:200])


# ── the checks; each returns Results and never raises ───────────────────────────────────────
def speed_level(ms: int) -> str:
    return FAIL if ms >= VERY_SLOW_MS else WARN if ms >= SLOW_MS else OK


def judge_page(path: str, want: int, needle: str | None, min_amounts: int, r: Response) -> tuple[str, str]:
    if r.status != want:
        return FAIL, f"HTTP {r.status or r.error or 'no answer'}, expected {want}"
    if needle and needle.lower() not in r.text.lower():
        return FAIL, f"{want} but the page does not hold {needle!r}"
    if min_amounts:
        n = len(AMOUNT.findall(r.text))
        if n < min_amounts:
            return FAIL, f"{want} but only {n} amounts (at least {min_amounts}): the data did not load"
    lvl = speed_level(r.ms)
    return lvl, f"{r.status} in {r.ms} ms" + (" (slow)" if lvl != OK else "")


def check_pages(base: str, ip: str | None, insecure: bool, target: str) -> list[Result]:
    out = []
    for path, want, needle, amounts in PAGES:
        r = fetch(base + path, connect_ip=ip, insecure=insecure, timeout=60)
        lvl, detail = judge_page(path, want, needle, amounts, r)
        out.append(Result(f"page {path}", lvl, detail, r.ms, target))
    for path in DATA_FILES:
        r = fetch(base + path, connect_ip=ip, insecure=insecure)
        lvl, detail = OK, f"{r.status} in {r.ms} ms"
        if r.status != 200:
            lvl, detail = FAIL, f"HTTP {r.status or r.error}"
        else:
            try:
                json.loads(r.body)
            except ValueError:
                lvl, detail = FAIL, "200 but not valid JSON"
        out.append(Result(f"data {path}", lvl, detail, r.ms, target))
    # one of the page's own script files: the release's build files are served
    r = fetch(base + "/fr", connect_ip=ip, insecure=insecure)
    m = re.search(r'/_next/static/[^"]+\.js', r.text)
    if not m:
        out.append(Result("script file of /fr", FAIL, "no /_next/static script in /fr", None, target))
    else:
        a = fetch(base + m.group(0), connect_ip=ip, insecure=insecure)
        out.append(Result("script file of /fr", OK if a.status == 200 else FAIL, f"{a.status or a.error}", a.ms, target))
    out.append(check_cache_headers(base, ip, insecure, target))
    return out


def served_by(headers: dict) -> str:
    if "x-vercel-id" in headers or headers.get("server", "").lower() == "vercel":
        return "vercel"
    if headers.get("server", "").lower() == "cloudflare" or "cf-ray" in headers:
        return "cloudflare"
    if headers.get("server", "").startswith("nginx") or "x-qipu-cache" in headers:
        return "server"
    return headers.get("server", "unknown") or "unknown"


def judge_cache(page_headers: dict, second_headers: dict, data_headers: dict) -> tuple[str, str]:
    """What a cache in front may keep: /data files an hour in the browser; on our server, pages marked
    for the edge and the page cache answering."""
    who = served_by(page_headers)
    dcc = data_headers.get("cache-control", "")
    if "max-age=" not in dcc:
        return FAIL, f"/data file has no max-age (Cache-Control: {dcc or 'none'}) [{who}]"
    if who == "vercel":
        return OK, f"served by Vercel, /data {dcc}"
    if who == "cloudflare":
        # The edge keeps Cloudflare-CDN-Cache-Control for itself (never passed on): its own
        # cf-cache-status says what it did. DYNAMIC = not stored at the edge, asked of the origin.
        cf = second_headers.get("cf-cache-status", "").upper()
        origin = second_headers.get("x-qipu-cache", "")
        detail = f"[cloudflare] /fr edge {cf or 'none'}" + (f", origin {origin}" if origin else "") + f", /data {dcc}"
        if cf in ("HIT", "MISS", "STALE", "REVALIDATED", "EXPIRED", "UPDATING", "DYNAMIC"):
            return OK, detail
        return WARN, detail + " (unexpected cf-cache-status)"
    # nginx: the page is marked for the edge, and the second ask comes from the page cache
    edge = page_headers.get("cloudflare-cdn-cache-control", "")
    if "s-maxage" not in edge:
        return FAIL, f"/fr not marked for the edge (Cloudflare-CDN-Cache-Control: {edge or 'none'}) [{who}]"
    hit = second_headers.get("x-qipu-cache", second_headers.get("cf-cache-status", ""))
    if hit.upper() not in ("HIT", "STALE", "UPDATING", "REVALIDATED"):
        return WARN, f"/fr asked twice, the second not from the cache (X-Qipu-Cache: {hit or 'none'}) [{who}]"
    return OK, f"[{who}] /fr {hit}, edge {edge.split(',')[0]}, /data {dcc}"


def check_cache_headers(base: str, ip: str | None, insecure: bool, target: str) -> Result:
    a = fetch(base + "/fr", connect_ip=ip, insecure=insecure)
    b = fetch(base + "/fr", connect_ip=ip, insecure=insecure)
    d = fetch(base + DATA_FILES[0], connect_ip=ip, insecure=insecure)
    if not (a.status == b.status == d.status == 200):
        return Result("cache headers", FAIL, f"/fr {a.status}/{b.status}, data {d.status}", None, target)
    lvl, detail = judge_cache(a.headers, b.headers, d.headers)
    return Result("cache headers", lvl, detail, b.ms, target)


def check_ask_alive(base: str, ip: str | None, insecure: bool, target: str) -> Result:
    """The assistant's route answers (no model call: an empty conversation is refused at once)."""
    r = fetch(base + "/api/chat", method="POST", body=b"{}", headers={"Content-Type": "application/json"},
              connect_ip=ip, insecure=insecure)
    if r.status == 400 and b"empty" in r.body:
        return Result("ask route", speed_level(r.ms), f"answers ({r.ms} ms)", r.ms, target)
    if r.status == 429:
        return Result("ask route", WARN, "429: the per-address limit of the assistant", r.ms, target)
    return Result("ask route", FAIL, f"HTTP {r.status or r.error}: {r.text[:120]}", r.ms, target)


def judge_ask_stream(status: int, text: str) -> tuple[str, str]:
    if status == 503 and ("share of questions" in text or "sa part de questions" in text):
        return WARN, "daily spending cap reached: the assistant refuses until midnight UTC"
    if status != 200:
        return FAIL, f"HTTP {status}: {text[:160]}"
    events = re.findall(r"^event: (\w+)", text, re.M)
    if "error" in events:
        m = re.search(r"event: error\ndata: (.*)", text)
        return FAIL, f"the assistant answered an error: {(m.group(1) if m else '')[:160]}"
    if "done" not in events:
        return FAIL, f"the answer stopped before the end (events: {','.join(events[-5:])})"
    answer = "".join(json.loads(d) if d.startswith('"') else "" for d in re.findall(r"^event: text\ndata: (.*)$", text, re.M))
    if not AMOUNT.search(answer):
        return FAIL, "the answer holds no amount"
    return OK, f"answered with amounts ({len(answer)} characters, tools: {events.count('tool')})"


def check_ask_live(base: str, ip: str | None, insecure: bool, target: str) -> Result:
    """One real question (one model call, a few cents): the key, the model, the tools, the data."""
    body = json.dumps({"messages": [{"role": "user", "content": ASK_QUESTION}], "scope": "paris", "locale": "fr"}).encode()
    r = fetch(base + "/api/chat", method="POST", body=body, connect_ip=ip, insecure=insecure, timeout=120,
              headers={"Content-Type": "application/json", "x-no-pinned": "1"})
    lvl, detail = judge_ask_stream(r.status, r.text if r.status else r.error)
    return Result("ask answers a question", lvl, f"{detail} in {r.ms} ms", r.ms, target)


def sign_action(secret: str, email: str, action: str, commune: str = "") -> str:
    """lib/abonnement/token.ts signAction: HMAC-SHA256, base64url without padding."""
    mac = hmac.new(secret.encode(), f"gerer\n{email}\n{action}\n{commune}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def check_alerts(base: str, ip: str | None, insecure: bool, target: str, secret: str | None) -> Result:
    """The alert mails' links work: with the secret, a signed link for an address no reader has is
    accepted (the site only reads Resend; nothing is sent, nothing changes). Without it: the route is up."""
    if not secret:
        r = fetch(base + "/api/abonnement/gerer", connect_ip=ip, insecure=insecure)
        lvl = OK if r.status == 405 else FAIL
        return Result("alert links", lvl, f"route up (GET {r.status or r.error}); add ALERTS_SECRET to check signatures", r.ms, target)
    q = urllib.parse.urlencode({"e": VERIF_EMAIL, "a": "essentiel", "s": sign_action(secret, VERIF_EMAIL, "essentiel")})
    r = fetch(f"{base}/api/abonnement/gerer?{q}", method="POST", connect_ip=ip, insecure=insecure)
    try:
        j = json.loads(r.body) if r.body else {}
    except ValueError:
        j = {}
    if r.status == 200 and j.get("ok"):
        return Result("alert links", OK, "a signed link is accepted; the site reads Resend", r.ms, target)
    if r.status == 400 and j.get("error") == "invalid_link":
        return Result("alert links", FAIL, "the site refuses links signed with ALERTS_SECRET: every unsubscribe link is broken", r.ms, target)
    if r.status == 503:
        return Result("alert links", FAIL, "the site has no alert configuration (Resend key, segment, sender or secret)", r.ms, target)
    return Result("alert links", FAIL, f"HTTP {r.status or r.error} {j.get('error', '')}".strip(), r.ms, target)


def check_tiles_and_data_site() -> list[Result]:
    out = []
    r = fetch(TILE_INDEX)
    ok = r.status == 200 and r.body[:1] == b"{"
    out.append(Result("tiles index", OK if ok else FAIL, f"{r.status or r.error} in {r.ms} ms", r.ms, "tiles"))
    r = fetch(TILE)
    ok = r.status == 200 and "image/" in r.headers.get("content-type", "") and len(r.body) > 1000
    out.append(Result("tiles sample tile", OK if ok else FAIL,
                      f"{r.status or r.error}, {r.headers.get('content-type', '?')}, {len(r.body)} bytes, {r.ms} ms", r.ms, "tiles"))
    url, needle = DATA_SITE
    r = fetch(url)
    ok = r.status == 200 and needle.lower() in r.text.lower()   # the site says "Qipu data"
    out.append(Result("data.qipu.org", OK if ok else FAIL, f"{r.status or r.error} in {r.ms} ms", r.ms, "data"))
    return out


# ── DNS (over HTTPS, two resolvers, so the runner's own resolver does not decide) ───────────
def doh(name: str, rtype: str, server: str) -> list[str] | None:
    url = f"{server}?name={urllib.parse.quote(name)}&type={rtype}"
    r = fetch(url, headers={"Accept": "application/dns-json"}, timeout=10)
    if r.status != 200:
        return None
    try:
        j = json.loads(r.body)
    except ValueError:
        return None
    if j.get("Status") != 0:
        return []
    return [a.get("data", "").rstrip(".") for a in j.get("Answer", [])]


def parse_expect(s: str) -> dict[str, str]:
    out = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower().rstrip(".")
    return out


def judge_dns(name: str, answers: dict[str, list[str] | None], expect: str | None) -> tuple[str, str]:
    got = {k: v for k, v in answers.items() if v is not None}
    if not got:
        return WARN, "no DNS-over-HTTPS resolver answered (the check, not the site)"
    empty = [k for k, v in got.items() if not v]
    if empty:
        return FAIL, f"does not resolve at {', '.join(empty)}"
    flat = sorted({a.lower() for v in got.values() for a in v})
    if expect and not any(expect in a for a in flat):
        return FAIL, f"resolves to {', '.join(flat)[:160]}, expected {expect}"
    return OK, ", ".join(flat)[:160]


def check_dns(expect: dict[str, str]) -> list[Result]:
    out = []
    for name in sorted(set(DNS_NAMES) | set(expect)):
        answers = {srv: doh(name, "A", url) for srv, url in
                   (("cloudflare", "https://cloudflare-dns.com/dns-query"), ("google", "https://dns.google/resolve"))}
        lvl, detail = judge_dns(name, answers, expect.get(name))
        out.append(Result(f"dns {name}", lvl, detail, None, "dns"))
    return out


# ── certificates ────────────────────────────────────────────────────────────────────────────
def cert_days(host: str, connect_ip: str | None = None) -> tuple[float | None, str]:
    """Days left on the certificate shown for host (checked against the system's roots)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_ip or host, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        end = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
        return (end - datetime.now(timezone.utc)).total_seconds() / 86400, issuer
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        return None, f"{type(e).__name__}: {e}"[:200]


def judge_cert(days: float | None, info: str) -> tuple[str, str]:
    if days is None:
        return FAIL, f"no valid certificate: {info}"
    lvl = FAIL if days < TLS_FAIL_DAYS else WARN if days < TLS_WARN_DAYS else OK
    return lvl, f"{days:.0f} days left ({info})"


def check_certs(base_host: str, origin_ip: str | None, insecure: bool) -> list[Result]:
    out = []
    for host in (base_host, "tiles.qipu.org", "data.qipu.org"):
        lvl, detail = judge_cert(*cert_days(host))
        out.append(Result(f"tls {host}", lvl, detail, None, "tls"))
    if origin_ip and not insecure:
        lvl, detail = judge_cert(*cert_days(base_host, origin_ip))
        out.append(Result(f"tls {base_host} at the server", lvl, detail, None, "origin"))
    return out


# ── the server's own numbers (/__ops/status) ────────────────────────────────────────────────
def judge_status(st: dict, now: float, prev_restarts: dict | None) -> list[tuple[str, str, str]]:
    """(name, level, detail) for each number of the server's status file."""
    out = []
    age = now - st.get("generated_at", 0)
    out.append(("server status fresh", FAIL if age > STATUS_STALE_S else OK,
                f"written {age:.0f} s ago" + (" (its timer stopped?)" if age > STATUS_STALE_S else "")))
    for d in st.get("disks", []):
        u = d.get("used_pct", 0)
        out.append((f"server disk {d.get('mount')}", FAIL if u >= DISK_FAIL else WARN if u >= DISK_WARN else OK,
                    f"{u:.0f} % used, {d.get('free_gb')} GB free"))
    tot, av = st.get("mem_total_mb") or 0, st.get("mem_available_mb") or 0
    if tot:
        p = 100.0 * av / tot
        out.append(("server memory", FAIL if p < MEM_FAIL else WARN if p < MEM_WARN else OK,
                    f"{av} of {tot} MB available ({p:.0f} %), swap {st.get('swap_used_mb', 0)} MB used"))
    cpus = st.get("cpus") or 1
    load1 = (st.get("load") or [0])[0]
    per = load1 / cpus
    out.append(("server load", FAIL if per >= LOAD_FAIL else WARN if per >= LOAD_WARN else OK,
                f"load {load1:.2f} on {cpus} CPUs, CPU {st.get('cpu_busy_pct')} % busy"))
    units = st.get("units", [])
    down = [u["name"] for u in units if u.get("active") != "active"]
    site = [u for u in units if u["name"].startswith("qipu-site@production")]
    if not site:
        out.append(("server processes", FAIL, "no production process listed"))
    elif down:
        out.append(("server processes", FAIL, f"not running: {', '.join(down)}"))
    else:
        mem = ", ".join(f"{u['name'].split('-')[-1]} {u.get('memory_mb')} MB" for u in site)
        out.append(("server processes", OK, f"{len(site)} site processes and nginx up ({mem})"))
    restarts = {u["name"]: u.get("restarts") or 0 for u in units}
    if prev_restarts is not None:
        more = {n: c - prev_restarts.get(n, 0) for n, c in restarts.items() if c > prev_restarts.get(n, 0)}
        out.append(("server restarts", WARN if more else OK,
                    ("restarted since the last run: " + ", ".join(f"{n} +{c}" for n, c in more.items())) if more else "none since the last run"))
    if "reboot_required" in st:
        out.append(("server reboot pending", WARN if st["reboot_required"] else OK,
                    f"an update waits for a reboot ({st.get('reboot_packages', 0)} packages): do it at a quiet hour (RELIABILITY.md)"
                    if st["reboot_required"] else "none"))
    days = st.get("cert_days_left")
    if days is not None:
        out.append(("server certificate file", FAIL if days < TLS_FAIL_DAYS else WARN if days < TLS_WARN_DAYS else OK,
                    f"{days:.0f} days left"))
    return out


def check_server_status(base: str, ip: str | None, insecure: bool, token: str, state: dict) -> tuple[list[Result], dict | None]:
    r = fetch(base + "/__ops/status", headers={"X-Qipu-Ops-Token": token}, connect_ip=ip, insecure=insecure)
    if r.status != 200:
        hint = " (404: wrong token, or the site is not on the server yet)" if r.status == 404 else ""
        return [Result("server status", FAIL, f"HTTP {r.status or r.error}{hint}", r.ms, "server")], None
    try:
        st = json.loads(r.body)
    except ValueError:
        return [Result("server status", FAIL, "not JSON", r.ms, "server")], None
    res = [Result(n, lvl, d, None, "server") for n, lvl, d in judge_status(st, time.time(), state.get("restarts"))]
    return res, st


# ── state and what to say ───────────────────────────────────────────────────────────────────
def decide(prev: dict, results: list[Result], now: float, remind_hours: float = 6) -> tuple[dict, list[dict]]:
    """Compare this run with the last ones. One message per kind of change:
       down     a check failing that was not (priority urgent)
       still    still failing, the last word on it older than remind_hours (priority high)
       recovered  failing before, not now (priority default)
       warn     a check newly in warning (priority low; no reminder)
    Returns the new state and the messages."""
    checks_prev = prev.get("checks", {})
    checks: dict = {}
    down, still, recovered, warned = [], [], [], []
    for r in results:
        p = checks_prev.get(r.name, {"level": OK, "since": now, "told": 0})
        c = {"level": r.level, "since": p["since"] if p["level"] == r.level else now, "told": p.get("told", 0),
             "detail": r.detail}
        if r.level == FAIL and p["level"] != FAIL:
            down.append(r)
            c["told"] = now
        elif r.level == FAIL and now - p.get("told", 0) >= remind_hours * 3600:
            still.append((r, now - p["since"]))
            c["told"] = now
        elif r.level != FAIL and p["level"] == FAIL:
            recovered.append((r, now - p["since"]))
            c["told"] = 0
        elif r.level == WARN and p["level"] == OK:
            warned.append(r)
        checks[r.name] = c
    # a check that is no longer run (no secret any more...) is forgotten, not "recovered"
    msgs = []
    if down:
        msgs.append({"kind": "down", "priority": 5, "tags": ["rotating_light"],
                     "title": f"qipu.org: {len(down)} check{'s' if len(down) > 1 else ''} failing",
                     "lines": [f"{r.name}: {r.detail}" for r in down]})
    if still:
        msgs.append({"kind": "still", "priority": 4, "tags": ["warning"],
                     "title": f"qipu.org: still failing ({len(still)})",
                     "lines": [f"{r.name}: {r.detail} (for {fmt_dur(d)})" for r, d in still]})
    if recovered:
        msgs.append({"kind": "recovered", "priority": 3, "tags": ["white_check_mark"],
                     "title": f"qipu.org: {len(recovered)} check{'s' if len(recovered) > 1 else ''} fixed",
                     "lines": [f"{r.name}: {r.detail} (was down {fmt_dur(d)})" for r, d in recovered]})
    if warned:
        msgs.append({"kind": "warn", "priority": 2, "tags": ["yellow_circle"],
                     "title": f"qipu.org: {len(warned)} warning{'s' if len(warned) > 1 else ''}",
                     "lines": [f"{r.name}: {r.detail}" for r in warned]})
    hist = [h for h in prev.get("history", []) if now - h["t"] < 48 * 3600]
    hist.append({"t": int(now), "fail": [r.name for r in results if r.level == FAIL],
                 "warn": [r.name for r in results if r.level == WARN],
                 "ms": {r.name: r.ms for r in results if r.ms is not None and r.name.startswith("page /fr")}})
    state = {"checks": checks, "history": hist, "restarts": prev.get("restarts"), "last_run": int(now)}
    return state, msgs


def fmt_dur(s: float) -> str:
    s = int(s)
    if s < 3600:
        return f"{max(1, s // 60)} min"
    if s < 86400:
        return f"{s // 3600} h {s % 3600 // 60:02d}"
    return f"{s // 86400} d {s % 86400 // 3600} h"


def summary(state: dict, results: list[Result], now: float, server: dict | None) -> dict:
    day = [h for h in state.get("history", []) if now - h["t"] < 86400]
    bad = [h for h in day if h["fail"]]
    gaps = sum(1 for a, b in zip(day, day[1:]) if b["t"] - a["t"] > 40 * 60)
    fr = sorted(h["ms"].get("page /fr") for h in day if h.get("ms", {}).get("page /fr") is not None)
    lines = [f"Last 24 h: {len(day)} runs, {len(bad)} with a failure" + (f", {gaps} gaps over 40 min (GitHub skipped runs)" if gaps else "")]
    if fr:
        lines.append(f"/fr answered in {fr[len(fr) // 2]} ms (median), {fr[-1]} ms at worst")
    failing = [r for r in results if r.level == FAIL]
    warning = [r for r in results if r.level == WARN]
    lines.append("Now: all checks pass" if not failing and not warning else
                 f"Now: {len(failing)} failing, {len(warning)} warnings")
    lines += [f"  FAIL {r.name}: {r.detail}" for r in failing] + [f"  warn {r.name}: {r.detail}" for r in warning]
    if server:
        disk = ", ".join(f"{d['mount']} {d['used_pct']:.0f} %" for d in server.get("disks", []))
        lines.append(f"Server: disk {disk}; memory {server.get('mem_available_mb')}/{server.get('mem_total_mb')} MB free; "
                     f"load {(server.get('load') or [0])[0]:.2f}; release {server.get('release')}; up {fmt_dur(server.get('uptime_s', 0))}")
    for r in results:
        if any(k in r.name for k in ("tls ", "ask answers", "alert links")):
            lines.append(f"{r.name}: {r.detail}")
    worst = FAIL if failing else WARN if warning else OK
    return {"kind": "summary", "priority": 3 if worst != OK else 2, "tags": ["bar_chart"],
            "title": f"qipu.org daily: {'all good' if worst == OK else worst}", "lines": lines}


# ── telling ─────────────────────────────────────────────────────────────────────────────────
def notify(msg: dict, env: dict, run_url: str) -> list[str]:
    """Send one message to every channel set up. Returns what failed (never raises)."""
    errors = []
    text = "\n".join(msg["lines"])[:3800]
    topic = env.get("NTFY_TOPIC")
    if topic:
        payload = {"topic": topic, "title": msg["title"], "message": text, "priority": msg["priority"], "tags": msg["tags"]}
        if run_url:
            payload["click"] = run_url
        headers = {"Content-Type": "application/json"}
        if env.get("NTFY_TOKEN"):
            headers["Authorization"] = f"Bearer {env['NTFY_TOKEN']}"
        r = fetch(env.get("NTFY_SERVER") or "https://ntfy.sh", method="POST", body=json.dumps(payload).encode(), headers=headers)
        if r.status != 200:
            errors.append(f"ntfy: HTTP {r.status or r.error}")
    if env.get("RESEND_API_KEY") and env.get("MAIL_TO") and msg["kind"] in ("down", "still", "recovered", "summary"):
        mail = {"from": env.get("MAIL_FROM") or "Qipu monitor <onboarding@resend.dev>",
                "to": [a.strip() for a in env["MAIL_TO"].split(",")], "subject": msg["title"],
                "text": text + (f"\n\nRun: {run_url}" if run_url else "")}
        r = fetch("https://api.resend.com/emails", method="POST", body=json.dumps(mail).encode(),
                  headers={"Authorization": f"Bearer {env['RESEND_API_KEY']}", "Content-Type": "application/json"})
        if r.status not in (200, 201):
            errors.append(f"resend: HTTP {r.status or r.error}")
    return errors


# ── a run ───────────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    base: str = "https://www.qipu.org"
    origin_ip: str | None = None
    insecure_origin: bool = False
    ops_token: str | None = None
    alerts_secret: str | None = None
    dns_expect: dict = field(default_factory=dict)
    summary: bool = False
    ask_live: bool = True
    only_origin: bool = False


def run_checks(cfg: Config, state: dict) -> tuple[list[Result], dict | None]:
    results: list[Result] = []
    host = urllib.parse.urlsplit(cfg.base).hostname or "www.qipu.org"
    targets = [] if cfg.only_origin else [("site", None, False)]
    if cfg.origin_ip:
        targets.append(("origin", cfg.origin_ip, cfg.insecure_origin))
    for target, ip, insecure in targets:
        res = check_pages(cfg.base, ip, insecure, target)
        res.append(check_ask_alive(cfg.base, ip, insecure, target))
        res.append(check_alerts(cfg.base, ip, insecure, target, cfg.alerts_secret))
        if cfg.summary and cfg.ask_live and target == targets[0][0]:
            res.append(check_ask_live(cfg.base, ip, insecure, target))
        if target == "origin":
            for r in res:
                r.name = f"server: {r.name}"
        results += res
    if not cfg.only_origin:
        results += check_tiles_and_data_site()
        results += check_dns(cfg.dns_expect)
    results += check_certs(host, cfg.origin_ip, cfg.insecure_origin or cfg.only_origin)
    server = None
    if cfg.ops_token:
        res, server = check_server_status(cfg.base, cfg.origin_ip, cfg.insecure_origin, cfg.ops_token, state)
        results += res
    return results, server


def recheck_failures(cfg: Config, results: list[Result], state: dict, wait: float) -> list[Result]:
    """A failure counts only if it is still there a little later: one blip is not an alert."""
    if not any(r.level == FAIL for r in results) or wait <= 0:
        return results
    time.sleep(wait)
    quick = Config(**{**cfg.__dict__, "summary": False})   # no second model call
    again, _ = run_checks(quick, state)
    by_name = {r.name: r for r in again}
    return [by_name.get(r.name, r) if r.level == FAIL else r for r in results]


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def print_results(results: list[Result], detail: bool = True) -> None:
    """detail=False (LOG_DETAIL=0, the public repository's logs): only the names of what is not ok."""
    for r in results:
        mark = {OK: "ok  ", WARN: "WARN", FAIL: "FAIL"}[r.level]
        if detail:
            print(f"{mark} [{r.target}] {r.name}: {r.detail}")
        elif r.level != OK:
            print(f"{mark} [{r.target}] {r.name}")
    n = {lvl: sum(1 for r in results if r.level == lvl) for lvl in (OK, WARN, FAIL)}
    print(f"\n{len(results)} checks: {n[OK]} ok, {n[WARN]} warnings, {n[FAIL]} failing")


def main(argv: list[str]) -> int:
    env = dict(os.environ)
    args = set(argv)

    def opt(name: str) -> str | None:
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None

    cfg = Config(
        base=(env.get("BASE_URL") or "https://www.qipu.org").rstrip("/"),
        origin_ip=opt("--origin") or env.get("ORIGIN_IP") or None,
        insecure_origin="--insecure-origin" in args or env.get("ORIGIN_INSECURE") == "1",
        ops_token=env.get("OPS_STATUS_TOKEN") or None,
        alerts_secret=env.get("ALERTS_SECRET") or None,
        dns_expect=parse_expect(env.get("DNS_EXPECT", "")),
        summary="--summary" in args,
        ask_live=env.get("ASK_LIVE", "1") == "1" and "--no-ask-live" not in args,
        only_origin="--only-origin" in args,
    )
    dry = "--dry-run" in args
    state_file = env.get("STATE_FILE") or "monitor-state.json"
    state = load_state(state_file)
    now = time.time()
    results, server = run_checks(cfg, state)
    results = recheck_failures(cfg, results, state, float(env.get("RECHECK_SECONDS", "20")))
    detail = env.get("LOG_DETAIL", "1") == "1"
    print_results(results, detail)

    new_state, msgs = decide(state, results, now, float(env.get("REMIND_HOURS", "6")))
    if server:
        new_state["restarts"] = {u["name"]: u.get("restarts") or 0 for u in server.get("units", [])}
    if cfg.summary:
        msgs.append(summary(new_state, results, now, server))
    run_url = ""
    if env.get("GITHUB_RUN_ID"):
        run_url = f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env.get('GITHUB_REPOSITORY')}/actions/runs/{env['GITHUB_RUN_ID']}"
    for m in msgs:
        print(f"\n>> {m['title']}" + ("\n   " + "\n   ".join(m["lines"]) if detail else ""))
    if dry:
        print("\n(dry run: nothing sent, no state written)")
        return 0
    errors = [e for m in msgs for e in notify(m, env, run_url)]
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(new_state, f)
    if env.get("HEARTBEAT_URL"):
        fetch(env["HEARTBEAT_URL"], timeout=10)
    for e in errors:
        print(f"::warning::could not notify: {e}")
    # Red in GitHub only when the alerting itself is broken: a failing site is told by push and
    # mail, not by a red run (which would also file a workflow-failure issue every ten minutes).
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
