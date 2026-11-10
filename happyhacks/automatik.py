"""Automatik relay + phone app (PWA) at happyhacks.io/automatik/.

The relay is a blind mailbox between the user's phone and their PC:
- The phone posts end-to-end encrypted requests (it also sends the user's token, which the relay
  checks against AUTOMATIK_TOKEN_HASH). The relay can't read or change them: they're encrypted to
  the PC and signed with the phone's passkey.
- The PC collects them by polling over HTTPS (its calls are signed with AUTOMATIK_RELAY_KEY) and
  posts encrypted replies, which the phone collects.
- The PC posts short alerts (no mail or calendar content). Urgent ones are also emailed to
  AUTOMATIK_ALERT_EMAIL.
There is no endpoint here that adds, replaces or removes a device: that happens only on the PC.
Old messages are deleted after AUTOMATIK_KEEP_MIN minutes. Settings (in .env, never in the repo):
  AUTOMATIK_TOKEN_HASH   sha256 hex of the user's token (from `python -m remote setup` on the PC)
  AUTOMATIK_RELAY_KEY    the PC's relay key (same place)
  AUTOMATIK_ALERT_EMAIL  where urgent alerts go (e.g. the user's own address)
  AUTOMATIK_PC_IPS       optional: comma-separated IPs the PC polls from (empty = any, key still required)
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time

from flask import Blueprint, Response, abort, jsonify, render_template, request

from . import settings

bp = Blueprint("automatik", __name__, url_prefix="/automatik")

MAX_REQUEST_BYTES = 180 * 1024 * 1024        # 5 attachments x 25 MB, base64-encoded, plus text
KEEP_MIN = int(os.environ.get("AUTOMATIK_KEEP_MIN", "30"))
ALERT_KEEP_DAYS = 7
PC_CLOCK_SKEW_S = 300
FAIL_LIMIT = 10                              # wrong tokens per IP before a 15-minute lockout
_lock = threading.Lock()
_fails: dict[str, list[float]] = {}


def _setting(name, default=""):
    return os.environ.get(name) or settings.get(name) or default


def _db():
    path = os.path.join(settings.data_dir(), "automatik_relay.sqlite")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS req (id TEXT PRIMARY KEY, created REAL, msg TEXT, taken REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS res (id TEXT PRIMARY KEY, created REAL, body TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS alert (id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, level TEXT, text TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    return c


def _cleanup(c):
    old = time.time() - KEEP_MIN * 60
    c.execute("DELETE FROM req WHERE created < ?", (old,))
    c.execute("DELETE FROM res WHERE created < ?", (old,))
    c.execute("DELETE FROM alert WHERE created < ?", (time.time() - ALERT_KEEP_DAYS * 86400,))


def _client_ip():
    return request.remote_addr or "?"


# ---- phone side: the user's token ----

def _token_ok():
    stored = _setting("AUTOMATIK_TOKEN_HASH")
    ip = _client_ip()
    now = time.time()
    with _lock:
        recent = [t for t in _fails.get(ip, []) if now - t < 900]
        _fails[ip] = recent
        if len(recent) >= FAIL_LIMIT:
            abort(429)
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if stored and token and hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), stored):
        return True
    with _lock:
        _fails.setdefault(ip, []).append(now)
    abort(401)


@bp.post("/api/request")
def api_request():
    _token_ok()
    if (request.content_length or 0) > MAX_REQUEST_BYTES:
        abort(413)
    body = request.get_json(silent=True) or {}
    msg = body.get("msg")
    if not isinstance(msg, dict) or not (("device" in msg and "box" in msg) or "enroll" in msg):
        abort(400)
    rid = secrets.token_urlsafe(12)
    with _db() as c:
        _cleanup(c)
        c.execute("INSERT INTO req (id, created, msg, taken) VALUES (?, ?, ?, NULL)", (rid, time.time(), json.dumps(msg)))
    return jsonify({"id": rid})


@bp.get("/api/result/<rid>")
def api_result(rid):
    _token_ok()
    with _db() as c:
        row = c.execute("SELECT body FROM res WHERE id = ?", (rid,)).fetchone()
        if row:
            c.execute("DELETE FROM res WHERE id = ?", (rid,))
            return jsonify({"status": "done", **json.loads(row["body"])})
        pending = c.execute("SELECT taken FROM req WHERE id = ?", (rid,)).fetchone()
    if not pending:
        return jsonify({"status": "gone"}), 404
    return jsonify({"status": "working" if pending["taken"] else "waiting"})


@bp.get("/api/alerts")
def api_alerts():
    _token_ok()
    since = request.args.get("since", type=float) or 0.0
    with _db() as c:
        rows = c.execute("SELECT id, created, level, text FROM alert WHERE created > ? ORDER BY id DESC LIMIT 50",
                         (since,)).fetchall()
    return jsonify({"alerts": [dict(r) for r in rows]})


@bp.get("/api/status")
def api_status():
    _token_ok()
    with _db() as c:
        row = c.execute("SELECT v FROM meta WHERE k = 'pc_seen'").fetchone()
    seen = float(row["v"]) if row else 0.0
    return jsonify({"pc_online": time.time() - seen < 30, "pc_seen_s_ago": int(time.time() - seen) if seen else None})


# ---- PC side: the relay key ----

def _pc_ok():
    key = _setting("AUTOMATIK_RELAY_KEY")
    ips = [i.strip() for i in _setting("AUTOMATIK_PC_IPS").split(",") if i.strip()]
    if not key or (ips and _client_ip() not in ips):
        abort(403)
    ts = request.headers.get("X-Automatik-Time", "")
    sig = request.headers.get("X-Automatik-Sig", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > PC_CLOCK_SKEW_S:
        abort(403)
    body = request.get_data() or b""
    msg = f"{request.method}\n{request.path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    if not hmac.compare_digest(hmac.new(key.encode(), msg, hashlib.sha256).hexdigest(), sig):
        abort(403)


@bp.get("/relay/poll")
def relay_poll():
    _pc_ok()
    now = time.time()
    with _db() as c:
        _cleanup(c)
        c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('pc_seen', ?)", (str(now),))
        rows = c.execute("SELECT id, msg FROM req WHERE taken IS NULL ORDER BY created LIMIT 5").fetchall()
        for r in rows:
            c.execute("UPDATE req SET taken = ? WHERE id = ?", (now, r["id"]))
    return jsonify({"requests": [{"id": r["id"], "msg": json.loads(r["msg"])} for r in rows]})


@bp.post("/relay/reply")
def relay_reply():
    _pc_ok()
    body = request.get_json(silent=True) or {}
    rid = str(body.get("id") or "")
    out = {k: body[k] for k in ("box", "error") if k in body}
    if not rid or not out:
        abort(400)
    with _db() as c:
        c.execute("INSERT OR REPLACE INTO res (id, created, body) VALUES (?, ?, ?)", (rid, time.time(), json.dumps(out)))
        c.execute("DELETE FROM req WHERE id = ?", (rid,))
    return jsonify({"ok": True})


@bp.post("/relay/alert")
def relay_alert():
    _pc_ok()
    body = request.get_json(silent=True) or {}
    level = "urgent" if body.get("level") == "urgent" else "normal"
    text = str(body.get("text") or "")[:200]
    if not text:
        abort(400)
    with _db() as c:
        c.execute("INSERT INTO alert (created, level, text) VALUES (?, ?, ?)", (time.time(), level, text))
    to = _setting("AUTOMATIK_ALERT_EMAIL")
    if level == "urgent" and to:
        try:
            from .notify import send_email
            send_email(to, "Automatik alert", text + "\n\n(Automatic alert from your Automatik PC via happyhacks.io.)")
        except Exception:
            pass   # the alert is still in the app
    return jsonify({"ok": True})


# ---- the app itself ----

@bp.get("/")
def app_page():
    resp = Response(render_template("automatik/app.html"))
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
                                               "media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@bp.get("/sw")
def service_worker():
    """Served from /automatik/ (not /static/) so it controls the app's pages."""
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "automatik", "sw.js")
    with open(path, encoding="utf-8") as f:
        resp = Response(f.read(), mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["Service-Worker-Allowed"] = "/automatik/"
    return resp


@bp.get("/manifest.webmanifest")
def manifest():
    return jsonify({"name": "Automatik", "short_name": "Automatik", "start_url": "/automatik/", "scope": "/automatik/",
                    "display": "standalone", "background_color": "#101418", "theme_color": "#101418",
                    "icons": [{"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
                              {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"}]})
