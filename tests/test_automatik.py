"""Automatik relay: token and PC-key checks, the request -> poll -> reply -> result round trip, alerts,
and that no route adds devices. Made-up keys only."""
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest

TOKEN = "a test token that is long enough"
KEY = "test-relay-key"


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ.update({"DATA_DIR": self.tmp, "AUTOMATIK_TOKEN_HASH": hashlib.sha256(TOKEN.encode()).hexdigest(),
                           "AUTOMATIK_RELAY_KEY": KEY, "AUTOMATIK_ALERT_EMAIL": ""})
        from happyhacks import automatik, create_app
        automatik._fails.clear()
        automatik._enrols.clear()
        self.app = create_app()
        self.c = self.app.test_client()

    def tearDown(self):
        for k in ("AUTOMATIK_TOKEN_HASH", "AUTOMATIK_RELAY_KEY", "AUTOMATIK_ALERT_EMAIL"):
            os.environ.pop(k, None)

    def phone(self, method, path, body=None, token=TOKEN):
        h = {"Authorization": "Bearer " + token}
        if method == "POST":
            return self.c.post(path, json=body, headers=h)
        return self.c.get(path, headers=h)

    def pc(self, method, path, body=None, key=KEY, ts=None):
        data = json.dumps(body).encode() if body is not None else b""
        ts = str(ts or int(time.time()))
        sig = hmac.new(key.encode(), f"{method}\n{path}\n{ts}\n{hashlib.sha256(data).hexdigest()}".encode(), hashlib.sha256).hexdigest()
        h = {"X-Automatik-Time": ts, "X-Automatik-Sig": sig, "Content-Type": "application/json"}
        if method == "POST":
            return self.c.post(path, data=data, headers=h)
        return self.c.get(path, headers=h)

    def test_round_trip(self):
        rid = self.phone("POST", "/automatik/api/request", {"msg": {"device": "dev_1", "box": "Y2lwaGVy"}}).json["id"]
        self.assertEqual(self.phone("GET", f"/automatik/api/result/{rid}").json["status"], "waiting")
        items = self.pc("GET", "/automatik/relay/poll").json["requests"]
        self.assertEqual(items[0]["msg"]["box"], "Y2lwaGVy")
        self.assertEqual(self.phone("GET", f"/automatik/api/result/{rid}").json["status"], "working")
        self.assertEqual(self.pc("GET", "/automatik/relay/poll").json["requests"], [])    # taken once
        self.pc("POST", "/automatik/relay/reply", {"id": rid, "box": "YW5zd2Vy"})
        r = self.phone("GET", f"/automatik/api/result/{rid}").json
        self.assertEqual((r["status"], r["box"]), ("done", "YW5zd2Vy"))
        self.assertEqual(self.phone("GET", f"/automatik/api/result/{rid}").status_code, 404)  # collected once
        self.assertTrue(self.phone("GET", "/automatik/api/status").json["pc_online"])

    def test_phone_needs_token(self):
        self.assertEqual(self.phone("POST", "/automatik/api/request", {"msg": {"device": "d", "box": "x"}}, token="wrong").status_code, 401)
        self.assertEqual(self.c.get("/automatik/api/alerts").status_code, 401)

    def test_lockout_after_wrong_tokens(self):
        for _ in range(10):
            self.phone("GET", "/automatik/api/status", token="nope")
        self.assertEqual(self.phone("GET", "/automatik/api/status").status_code, 429)

    def test_pc_needs_key_and_fresh_time(self):
        self.assertEqual(self.pc("GET", "/automatik/relay/poll", key="wrong").status_code, 403)
        self.assertEqual(self.pc("GET", "/automatik/relay/poll", ts=int(time.time()) - 3600).status_code, 403)
        self.assertEqual(self.c.get("/automatik/relay/poll").status_code, 403)
        # a phone token doesn't open the PC side
        self.assertEqual(self.phone("GET", "/automatik/relay/poll").status_code, 403)

    def test_pc_body_is_signed(self):
        data = json.dumps({"id": "x", "box": "a"}).encode()
        ts = str(int(time.time()))
        sig = hmac.new(KEY.encode(), f"POST\n/automatik/relay/reply\n{ts}\n{hashlib.sha256(data).hexdigest()}".encode(), hashlib.sha256).hexdigest()
        r = self.c.post("/automatik/relay/reply", data=json.dumps({"id": "x", "box": "CHANGED"}),
                        headers={"X-Automatik-Time": ts, "X-Automatik-Sig": sig, "Content-Type": "application/json"})
        self.assertEqual(r.status_code, 403)

    def test_alerts(self):
        self.pc("POST", "/automatik/relay/alert", {"level": "urgent", "text": "A new device was enrolled."})
        a = self.phone("GET", "/automatik/api/alerts").json["alerts"]
        self.assertEqual((a[0]["level"], a[0]["text"]), ("urgent", "A new device was enrolled."))

    def test_enrolment_without_token(self):
        msg = {"enroll": {"box_public": "a2V5", "box": "Ym94"}}
        rid = self.c.post("/automatik/api/request", json={"msg": msg}).json["id"]
        self.assertTrue(rid.startswith("e"))
        self.assertEqual(self.c.get(f"/automatik/api/result/{rid}").json["status"], "waiting")
        self.pc("POST", "/automatik/relay/reply", {"id": rid, "box": "cmVwbHk="})
        self.assertEqual(self.c.get(f"/automatik/api/result/{rid}").json["box"], "cmVwbHk=")
        # only enrolment: a device message without the token is refused, and so is its result
        self.assertEqual(self.c.post("/automatik/api/request", json={"msg": {"device": "d", "box": "x"}}).status_code, 401)
        r2 = self.phone("POST", "/automatik/api/request", {"msg": {"device": "d", "box": "x"}}).json["id"]
        self.assertEqual(self.c.get(f"/automatik/api/result/{r2}").status_code, 401)
        # too big, and too many per hour
        self.assertEqual(self.c.post("/automatik/api/request", json={"msg": {"enroll": {"box": "x" * 20000}}}).status_code, 413)
        for _ in range(9):
            self.c.post("/automatik/api/request", json={"msg": msg})
        self.assertEqual(self.c.post("/automatik/api/request", json={"msg": msg}).status_code, 429)

    def test_bad_messages(self):
        self.assertEqual(self.phone("POST", "/automatik/api/request", {"msg": {"hello": 1}}).status_code, 400)

    def test_no_device_routes(self):
        rules = [str(r) for r in self.app.url_map.iter_rules() if str(r).startswith("/automatik")]
        for r in rules:
            self.assertNotRegex(r, r"enrol|device|passkey|revoke|register", r)

    def test_app_page(self):
        r = self.c.get("/automatik/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertIn("/static/automatik/app.js", r.get_data(as_text=True))
        sw = self.c.get("/automatik/sw")
        self.assertEqual(sw.headers["Service-Worker-Allowed"], "/automatik/")
        self.assertEqual(self.c.get("/automatik/manifest.webmanifest").json["scope"], "/automatik/")


if __name__ == "__main__":
    unittest.main()
