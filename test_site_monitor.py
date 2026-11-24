"""site_monitor.py without the internet: the judgements, the alerting rules, the signature, and one
real HTTP exchange with a local server (the connect-to-an-address path).

Run: python3 -m unittest discover -s ops/monitor -p "test_*.py" -v
"""
import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import site_monitor as m  # noqa: E402

FAIL, WARN, OK = m.FAIL, m.WARN, m.OK


def res(name, level, detail="d"):
    return m.Result(name, level, detail)


def page(status=200, body="", ms=100):
    return m.Response(status, {}, body.encode(), ms)


class Decide(unittest.TestCase):
    def test_first_failure_tells_once_then_silence(self):
        s1, msgs = m.decide({}, [res("page /fr", FAIL), res("tiles", OK)], now=1000)
        self.assertEqual([x["kind"] for x in msgs], ["down"])
        self.assertIn("page /fr", msgs[0]["lines"][0])
        s2, msgs = m.decide(s1, [res("page /fr", FAIL), res("tiles", OK)], now=1600)
        self.assertEqual(msgs, [])
        s3, msgs = m.decide(s2, [res("page /fr", FAIL), res("tiles", OK)], now=2200)
        self.assertEqual(msgs, [])

    def test_reminder_after_remind_hours(self):
        s, _ = m.decide({}, [res("a", FAIL)], now=0)
        s, msgs = m.decide(s, [res("a", FAIL)], now=5 * 3600, remind_hours=6)
        self.assertEqual(msgs, [])
        s, msgs = m.decide(s, [res("a", FAIL)], now=6 * 3600 + 1, remind_hours=6)
        self.assertEqual([x["kind"] for x in msgs], ["still"])
        self.assertIn("6 h", msgs[0]["lines"][0])
        s, msgs = m.decide(s, [res("a", FAIL)], now=7 * 3600, remind_hours=6)
        self.assertEqual(msgs, [])

    def test_recovery_said_once_with_duration(self):
        s, _ = m.decide({}, [res("a", FAIL)], now=0)
        s, msgs = m.decide(s, [res("a", OK)], now=1800)
        self.assertEqual([x["kind"] for x in msgs], ["recovered"])
        self.assertIn("30 min", msgs[0]["lines"][0])
        s, msgs = m.decide(s, [res("a", OK)], now=2400)
        self.assertEqual(msgs, [])

    def test_failure_to_warning_is_a_recovery(self):
        s, _ = m.decide({}, [res("a", FAIL)], now=0)
        _, msgs = m.decide(s, [res("a", WARN)], now=600)
        self.assertEqual([x["kind"] for x in msgs], ["recovered"])

    def test_warning_low_priority_and_once(self):
        s, msgs = m.decide({}, [res("disk", WARN)], now=0)
        self.assertEqual([(x["kind"], x["priority"]) for x in msgs], [("warn", 2)])
        _, msgs = m.decide(s, [res("disk", WARN)], now=99999)
        self.assertEqual(msgs, [])

    def test_several_changes_one_message_each_kind(self):
        s, _ = m.decide({}, [res("a", FAIL), res("b", OK), res("c", OK)], now=0)
        _, msgs = m.decide(s, [res("a", OK), res("b", FAIL), res("c", FAIL)], now=600)
        kinds = {x["kind"]: x for x in msgs}
        self.assertEqual(set(kinds), {"down", "recovered"})
        self.assertEqual(len(kinds["down"]["lines"]), 2)
        self.assertEqual(kinds["down"]["priority"], 5)

    def test_history_kept_two_days(self):
        s = {"history": [{"t": 0, "fail": [], "warn": [], "ms": {}}]}
        s, _ = m.decide(s, [res("a", OK)], now=49 * 3600)
        self.assertEqual(len(s["history"]), 1)


class Summary(unittest.TestCase):
    def test_counts_runs_failures_and_gaps(self):
        hist = [{"t": t, "fail": (["x"] if t == 1200 else []), "warn": [], "ms": {"page /fr": 100 + t // 600}}
                for t in (0, 600, 1200, 1800, 6000)]
        msg = m.summary({"history": hist}, [res("a", OK)], now=6000, server=None)
        self.assertIn("5 runs, 1 with a failure, 1 gaps", msg["lines"][0])
        self.assertIn("all good", msg["title"])

    def test_failing_now_listed(self):
        msg = m.summary({"history": []}, [res("page /fr", FAIL, "HTTP 502")], now=0, server=None)
        self.assertIn("FAIL page /fr: HTTP 502", "\n".join(msg["lines"]))


class Judgements(unittest.TestCase):
    def test_page(self):
        self.assertEqual(m.judge_page("/fr", 200, 'lang="fr"', 0, page(200, '<html data-x lang="fr">'))[0], OK)
        self.assertEqual(m.judge_page("/fr", 200, 'lang="fr"', 0, page(502, ""))[0], FAIL)
        self.assertEqual(m.judge_page("/fr", 200, 'lang="fr"', 0, page(200, "<html>"))[0], FAIL)
        self.assertEqual(m.judge_page("/", 307, None, 0, page(307))[0], OK)
        # headings but no data: too few amounts
        lvl, why = m.judge_page("/b", 200, "€", 3, page(200, "Budget € 12 €"))
        self.assertEqual(lvl, FAIL)
        self.assertIn("amounts", why)
        self.assertEqual(m.judge_page("/b", 200, "€", 3, page(200, "1 234 € 5 € 6,5 M€"))[0], OK)
        self.assertEqual(m.judge_page("/fr", 200, None, 0, page(200, "", ms=5000))[0], WARN)
        self.assertEqual(m.judge_page("/fr", 200, None, 0, page(200, "", ms=25000))[0], FAIL)

    def test_cache_on_vercel_and_on_the_server(self):
        data = {"cache-control": "public, max-age=3600, s-maxage=86400"}
        self.assertEqual(m.judge_cache({"server": "Vercel"}, {}, data)[0], OK)
        self.assertEqual(m.judge_cache({"server": "Vercel"}, {}, {})[0], FAIL)
        srv = {"server": "nginx/1.28", "cloudflare-cdn-cache-control": "public, s-maxage=604800", "x-qipu-cache": "MISS"}
        self.assertEqual(m.judge_cache(srv, {"x-qipu-cache": "HIT"}, data)[0], OK)
        self.assertEqual(m.judge_cache(srv, {"x-qipu-cache": "MISS"}, data)[0], WARN)
        self.assertEqual(m.judge_cache({"server": "nginx"}, {"x-qipu-cache": "HIT"}, data)[0], FAIL)
        # behind Cloudflare the edge strips Cloudflare-CDN-Cache-Control; its own cf-cache-status counts
        cf = {"server": "cloudflare", "cf-ray": "x", "cache-control": "s-maxage=31536000"}
        for status in ("HIT", "MISS", "DYNAMIC", "STALE", "REVALIDATED", "EXPIRED"):
            self.assertEqual(m.judge_cache(cf, {"cf-cache-status": status, "x-qipu-cache": "HIT"}, data)[0], OK, status)
        self.assertEqual(m.judge_cache(cf, {"cf-cache-status": "BYPASS"}, data)[0], WARN)
        self.assertEqual(m.judge_cache(cf, {}, data)[0], WARN)
        self.assertEqual(m.judge_cache(cf, {"cf-cache-status": "HIT"}, {})[0], FAIL)
        # the server's own address still has to mark pages for the edge
        self.assertEqual(m.judge_cache({"server": "nginx/1.28", "x-qipu-cache": "HIT"}, {"x-qipu-cache": "HIT"}, data)[0], FAIL)

    def test_ask_stream(self):
        good = 'event: tool\ndata: {"name":"x"}\n\nevent: text\ndata: "La dette est de 1 234 €"\n\nevent: done\ndata: {}\n\n'
        self.assertEqual(m.judge_ask_stream(200, good)[0], OK)
        self.assertEqual(m.judge_ask_stream(200, good.replace("1 234 €", "grande"))[0], FAIL)
        self.assertEqual(m.judge_ask_stream(200, 'event: text\ndata: "1 €"\n\nevent: error\ndata: {"message":"x"}\n\n')[0], FAIL)
        self.assertEqual(m.judge_ask_stream(200, 'event: text\ndata: "1 €"\n\n')[0], FAIL)
        self.assertEqual(m.judge_ask_stream(500, '{"error":"missing key"}')[0], FAIL)
        self.assertEqual(m.judge_ask_stream(503, '{"error":"L\'assistant a répondu à sa part de questions"}')[0], WARN)
        self.assertEqual(m.judge_ask_stream(503, "Service Unavailable")[0], FAIL)

    def test_signature_matches_the_site(self):
        # node: createHmac("sha256","s3cret").update("gerer\n<email>\nessentiel\n").digest("base64url")
        self.assertEqual(m.sign_action("s3cret", m.VERIF_EMAIL, "essentiel"), "WR0kyjWuPAkh75CS8LcfmKTb9cmfHnX4XmIbPhnp4Dk")

    def test_dns(self):
        self.assertEqual(m.judge_dns("w", {"a": ["1.2.3.4"], "b": ["1.2.3.4"]}, None)[0], OK)
        self.assertEqual(m.judge_dns("w", {"a": ["1.2.3.4"], "b": []}, None)[0], FAIL)
        self.assertEqual(m.judge_dns("w", {"a": None, "b": None}, None)[0], WARN)
        self.assertEqual(m.judge_dns("w", {"a": ["x.vercel-dns-017.com", "216.150.1.1"]}, "203.0.113.7")[0], FAIL)
        self.assertEqual(m.judge_dns("w", {"a": ["203.0.113.7"], "b": None}, "203.0.113.7")[0], OK)
        self.assertEqual(m.parse_expect(" www.qipu.org=203.0.113.7 , qipu.org = 203.0.113.7."),
                         {"www.qipu.org": "203.0.113.7", "qipu.org": "203.0.113.7"})

    def test_cert(self):
        self.assertEqual(m.judge_cert(None, "SSLError")[0], FAIL)
        self.assertEqual(m.judge_cert(3, "LE")[0], FAIL)
        self.assertEqual(m.judge_cert(15, "LE")[0], WARN)
        self.assertEqual(m.judge_cert(60, "LE")[0], OK)


class ServerStatus(unittest.TestCase):
    ST = {
        "generated_at": 1000, "cpus": 4, "load": [0.5, 0.4, 0.3], "cpu_busy_pct": 3.0,
        "mem_total_mb": 8000, "mem_available_mb": 6000, "swap_used_mb": 0,
        "disks": [{"mount": "/", "used_pct": 15.0, "free_gb": 60}],
        "units": [{"name": "nginx", "active": "active", "restarts": 0},
                  {"name": "qipu-site@production-3000", "active": "active", "restarts": 1, "memory_mb": 900},
                  {"name": "qipu-site@production-3001", "active": "active", "restarts": 0, "memory_mb": 400}],
        "cert_days_left": 80,
    }

    def levels(self, st, now=1030, prev=None):
        return {n: lvl for n, lvl, _ in m.judge_status(st, now, prev)}

    def test_healthy(self):
        lv = self.levels(self.ST, prev={"qipu-site@production-3000": 1})
        self.assertTrue(all(v == OK for v in lv.values()), lv)

    def test_each_limit(self):
        self.assertEqual(self.levels(self.ST, now=1000 + 600)["server status fresh"], FAIL)
        self.assertEqual(self.levels({**self.ST, "disks": [{"mount": "/", "used_pct": 88}]})["server disk /"], WARN)
        self.assertEqual(self.levels({**self.ST, "disks": [{"mount": "/", "used_pct": 95}]})["server disk /"], FAIL)
        self.assertEqual(self.levels({**self.ST, "mem_available_mb": 300})["server memory"], FAIL)
        self.assertEqual(self.levels({**self.ST, "load": [9.0, 1, 1]})["server load"], WARN)
        down = [dict(u, active="failed") if u["name"].endswith("3001") else u for u in self.ST["units"]]
        self.assertEqual(self.levels({**self.ST, "units": down})["server processes"], FAIL)
        self.assertEqual(self.levels({**self.ST, "units": self.ST["units"][:1]})["server processes"], FAIL)

    def test_reboot_pending_is_a_warning(self):
        self.assertEqual(self.levels({**self.ST, "reboot_required": False})["server reboot pending"], OK)
        self.assertEqual(self.levels({**self.ST, "reboot_required": True, "reboot_packages": 3})["server reboot pending"], WARN)

    def test_restarts_counted_between_runs(self):
        self.assertNotIn("server restarts", self.levels(self.ST, prev=None))
        self.assertEqual(self.levels(self.ST, prev={"qipu-site@production-3000": 0})["server restarts"], WARN)


class Fetch(unittest.TestCase):
    """One real exchange: connect to an address while asking for another name, gzip, no redirects."""

    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(307)
                    self.send_header("Location", "/fr")
                    self.end_headers()
                    return
                import gzip
                body = gzip.compress(json.dumps({"host": self.headers["Host"], "ua": self.headers["User-Agent"]}).encode())
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_connect_ip_keeps_the_name(self):
        r = m.fetch(f"http://www.example.test:{self.port}/x", connect_ip="127.0.0.1")
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)["host"], "www.example.test")
        self.assertTrue(json.loads(r.body)["ua"].startswith("qipu-site-monitor"))

    def test_redirect_not_followed(self):
        self.assertEqual(m.fetch(f"http://127.0.0.1:{self.port}/redirect").status, 307)

    def test_nobody_there_is_status_0(self):
        r = m.fetch("http://127.0.0.1:9/", timeout=2)
        self.assertEqual(r.status, 0)
        self.assertTrue(r.error)


class Notify(unittest.TestCase):
    def test_nothing_set_nothing_sent(self):
        self.assertEqual(m.notify({"kind": "down", "title": "t", "lines": ["x"], "priority": 5, "tags": []}, {}, ""), [])

    def test_ntfy_payload(self):
        sent = {}

        def fake(url, **kw):
            sent["url"], sent["body"], sent["headers"] = url, json.loads(kw["body"]), kw["headers"]
            return m.Response(200, {}, b"{}", 1)

        orig, m.fetch = m.fetch, fake
        try:
            errs = m.notify({"kind": "down", "title": "qipu.org: 1 check failing", "lines": ["page /fr: 502"], "priority": 5,
                             "tags": ["rotating_light"]}, {"NTFY_TOPIC": "t-123", "NTFY_TOKEN": "tok"}, "https://run")
        finally:
            m.fetch = orig
        self.assertEqual(errs, [])
        self.assertEqual(sent["url"], "https://ntfy.sh")
        self.assertEqual(sent["body"]["topic"], "t-123")
        self.assertEqual(sent["body"]["priority"], 5)
        self.assertEqual(sent["body"]["click"], "https://run")
        self.assertEqual(sent["headers"]["Authorization"], "Bearer tok")


if __name__ == "__main__":
    unittest.main()
