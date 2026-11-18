#!/usr/bin/env python3
"""Create the simple 5-minute checks on UptimeRobot (free plan), in one go, from its API key.

    UPTIMEROBOT_API_KEY=... SERVER_IP=<server address> python3 uptimerobot_setup.py   # create what is missing
    python3 uptimerobot_setup.py --dry-run                            # print the list, change nothing

The key: UptimeRobot -> Integrations & API -> API -> Main API key. Every monitor gets every alert
contact of the account (the e-mail it was opened with, and the phone once the UptimeRobot app is
signed in), so install the app and sign in BEFORE running this. Running it again adds only the
monitors whose name is not there yet. Standard library only; the free API allows 10 calls a minute,
so it waits between calls (about two minutes in all).

These are the outside-of-GitHub layer: plain status and a word on the page, every 5 minutes, from
UptimeRobot's own machines. The deeper checks (the assistant, the alert links, cache headers, DNS,
certificates, the server's disk and memory) are site_monitor.py's.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request

API = "https://api.uptimerobot.com/v2/"
HTTP, KEYWORD, PORT = 1, 2, 4
KEYWORD_NOT_EXISTS = 2   # the monitor is down when the word is NOT on the page
CASE_INSENSITIVE = 1
PORT_HTTPS = 2

# name, type, url, keyword (None for a plain status check)
MONITORS = [
    ("qipu home /fr", KEYWORD, "https://www.qipu.org/fr", 'lang="fr"'),
    ("qipu Paris budget (amounts)", KEYWORD, "https://www.qipu.org/fr/france/paris/budget", "€"),
    ("qipu commune page (R2 bucket)", KEYWORD, "https://www.qipu.org/fr/france/draguignan", "€"),
    ("qipu SF map page", KEYWORD, "https://www.qipu.org/en/usa/san-francisco/the-city", 'lang="en"'),
    ("qipu search API", KEYWORD, "https://www.qipu.org/api/search-communes?q=drag", "draguignan"),
    ("qipu data file", KEYWORD, "https://www.qipu.org/data/budget_index.json", "{"),
    ("qipu tiles sample tile", HTTP, "https://tiles.qipu.org/us/sf/city/r20261001/render/0/0/0.webp", None),
    ("qipu data site", KEYWORD, "https://data.qipu.org/", "qipu data"),
    ("qipu apex qipu.org", HTTP, "https://qipu.org/", None),
]
SERVER_IP = os.environ.get("SERVER_IP", "")   # the server's address (kept out of the public copy)


def call(method: str, params: dict) -> dict:
    data = urllib.parse.urlencode({**params, "api_key": os.environ["UPTIMEROBOT_API_KEY"], "format": "json"}).encode()
    req = urllib.request.Request(API + method, data=data, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                                   "Cache-Control": "no-cache", "User-Agent": "qipu-monitor-setup"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.load(r)
    time.sleep(7)   # 10 calls a minute on the free plan
    if out.get("stat") != "ok":
        raise SystemExit(f"{method}: {out.get('error', out)}")
    return out


def plan() -> list[dict]:
    out = []
    for name, kind, url, word in MONITORS:
        p = {"friendly_name": name, "url": url, "type": kind, "interval": 300, "timeout": 30}
        if kind == KEYWORD:
            p.update(keyword_type=KEYWORD_NOT_EXISTS, keyword_case_type=CASE_INSENSITIVE, keyword_value=word)
        out.append(p)
    # the server itself, by address: answers on 443 even when the names point elsewhere or the edge is down
    if SERVER_IP:
        out.append({"friendly_name": "qipu server port 443", "url": SERVER_IP, "type": PORT, "sub_type": PORT_HTTPS, "interval": 300})
    return out


def main() -> int:
    monitors = plan()
    if "--dry-run" in sys.argv or not os.environ.get("UPTIMEROBOT_API_KEY"):
        for m in monitors:
            print(json.dumps(m, ensure_ascii=False))
        if not os.environ.get("UPTIMEROBOT_API_KEY"):
            print("\n(UPTIMEROBOT_API_KEY not set: nothing created)")
        return 0
    contacts = call("getAlertContacts", {}).get("alert_contacts", [])
    if not contacts:
        raise SystemExit("the account has no alert contact yet: confirm the e-mail and sign in to the app first")
    ac = "-".join(f"{c['id']}_0_0" for c in contacts)
    print(f"alert contacts: {', '.join(str(c.get('friendly_name') or c.get('value')) for c in contacts)}")
    have = {m["friendly_name"] for m in call("getMonitors", {"limit": 50}).get("monitors", [])}
    for m in monitors:
        if m["friendly_name"] in have:
            print(f"there already: {m['friendly_name']}")
            continue
        call("newMonitor", {**m, "alert_contacts": ac})
        print(f"created: {m['friendly_name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
