"""Hidden admin: happyhacks.io/admin answers 404 until a Happy Hacks administrator unlocks it.

How it opens:
  - Signed in as an administrator, on /account: type the unlock word (ADMIN_UNLOCK_KEYS, default "unlock") within
    10 seconds of the page loading, or tap the "Hi, ..." heading 5 times quickly. A code box appears; enter the 6-digit
    code from your authenticator app. Admin then stays open for this browser for 30 minutes after your last admin
    page or action, and never longer than 12 hours in a row.
  - Recovery only: with ADMIN_RECOVERY=1 *and* ADMIN_PASSWORD set in .env, /admin/login takes the password. Turn
    ADMIN_RECOVERY off again as soon as you're back in.

Authenticators are set up on the server, never in the browser (someone who takes over your email or phone can't add
their own):
    python -m happyhacks.accounts totp you@example.com       (prints the setup key and a QR link)
    python -m happyhacks.accounts totp-off you@example.com
Unlocks, blocked unlocks, recovery sign-ins, a new network address, website updates and administrator / authenticator
changes are emailed to ADMIN_ALERT_EMAIL (comma-separated) and to the administrator concerned.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote

from flask import request, session

log = logging.getLogger('happyhacks.admin')

UNLOCK_MINUTES = 30
MAX_HOURS = 12
FAILS_ALLOWED = 5          # wrong codes per person (or recovery passwords per IP) ...
FAIL_WINDOW = 15 * 60      # ... in this many seconds
STEP = 30
ISSUER = 'Happy Hacks admin'


# ------------------------------------------------------------------ TOTP (RFC 6238, SHA-1, 6 digits, 30 s)

def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _key(secret):
    s = secret.upper().replace(' ', '')
    return base64.b32decode(s + '=' * (-len(s) % 8))


def code_at(secret, step):
    digest = hmac.new(_key(secret), struct.pack('>Q', step), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def check_code(secret, code, last_step=0, now=None):
    """The time step the code belongs to (now, or 30 s either side), or None. A step at or before last_step is
    refused, so a code can't be used twice."""
    code = ''.join(ch for ch in str(code or '') if ch.isdigit())
    if not secret or len(code) != 6:
        return None
    step = int((now if now is not None else time.time()) // STEP)
    for s in (step, step - 1, step + 1):
        if s > (last_step or 0) and hmac.compare_digest(code_at(secret, s), code):
            return s
    return None


def setup_uri(secret, account):
    return f'otpauth://totp/{quote(f"{ISSUER}:{account}")}?secret={secret}&issuer={quote(ISSUER)}&digits=6&period={STEP}'


# ------------------------------------------------------------------ settings

def recovery_on():
    return str(os.environ.get('ADMIN_RECOVERY', '')).strip().lower() in ('1', 'true', 'yes', 'on') \
        and bool(os.environ.get('ADMIN_PASSWORD', ''))


def unlock_keys():
    return (os.environ.get('ADMIN_UNLOCK_KEYS') or 'unlock').strip().lower()[:40] or 'unlock'


# ------------------------------------------------------------------ events (failed tries, across all workers)

def _db():
    from . import accounts
    return accounts.db()


def _event(kind, ref):
    _db().run('INSERT INTO admin_events (at, kind, ref) VALUES (%s,%s,%s)', (time.time(), kind, str(ref)[:64]))


def _recent(kind, ref):
    _db().run('DELETE FROM admin_events WHERE at < %s', (time.time() - 86400,))
    return _db().run('SELECT COUNT(*) AS n FROM admin_events WHERE kind=%s AND ref=%s AND at > %s',
                     (kind, str(ref)[:64], time.time() - FAIL_WINDOW), fetch='one')['n']


# ------------------------------------------------------------------ the unlock itself

def _admin_user():
    from .account_web import current_user
    u = current_user()
    return u if u and u.get('role') == 'admin' else None


def unlocked():
    u, lk = _admin_user(), session.get('admin_unlock')
    if not u or not isinstance(lk, dict) or lk.get('uid') != u['id']:
        return False
    now = time.time()
    return now < lk.get('until', 0) and now - lk.get('since', 0) < MAX_HOURS * 3600


def expired_for_admin():
    """An administrator whose unlock ran out (they're sent back to unlock; everyone else gets a plain 404)."""
    return bool(_admin_user()) and not unlocked()


def touch():
    lk = dict(session.get('admin_unlock') or {})
    lk['until'] = time.time() + UNLOCK_MINUTES * 60
    ip = request.remote_addr or ''
    if ip and lk.get('ip') and ip != lk['ip']:
        u = _admin_user()
        who = _who(u)
        log.warning('admin %s moved from %s to %s', who, lk['ip'], ip)
        alert(u, 'Admin is being used from a new network address',
              f'{who} unlocked admin from {lk["ip"]} and is now using it from {ip}.\n'
              "That's normal when a phone moves between Wi-Fi and mobile data. If it wasn't you, sign out everywhere "
              f'on happyhacks.io/account and run: python -m happyhacks.accounts totp-off {who}')
    lk['ip'] = ip or lk.get('ip', '')
    session['admin_unlock'] = lk


def lock():
    session.pop('admin_unlock', None)


def has_totp(u):
    row = _db().run('SELECT totp_secret FROM users WHERE id=%s', (u['id'],), fetch='one')
    return bool(row and row.get('totp_secret'))


def try_unlock(code):
    """Unlock for the signed-in administrator. Returns '' on success, or what went wrong in words."""
    u = _admin_user()
    if not u:
        return 'not_admin'
    who, ip = _who(u), request.remote_addr or ''
    if _recent('unlock_failed', u['id']) >= FAILS_ALLOWED:
        return 'Too many wrong codes. Wait 15 minutes and try again.'
    row = _db().run('SELECT totp_secret, totp_last_step FROM users WHERE id=%s', (u['id'],), fetch='one') or {}
    if not row.get('totp_secret'):
        return f'No authenticator is set up for you yet. On the server, run: python -m happyhacks.accounts totp {who}'
    step = check_code(row['totp_secret'], code, row.get('totp_last_step') or 0)
    if step is None:
        _event('unlock_failed', u['id'])
        log.warning('admin unlock: wrong code for %s from %s', who, ip)
        if _recent('unlock_failed', u['id']) == FAILS_ALLOWED:
            alert(u, 'Admin unlock blocked after wrong codes',
                  f'{FAILS_ALLOWED} wrong authenticator codes were entered for {who} (last from {ip}). Unlocking is '
                  "blocked for 15 minutes. If this wasn't you, someone can sign in as you: sign out everywhere.")
        return "That code didn't work. Codes change every 30 seconds; use the one showing now."
    _db().run('UPDATE users SET totp_last_step=%s WHERE id=%s', (step, u['id']))
    now = time.time()
    session['admin_unlock'] = {'uid': u['id'], 'since': now, 'until': now + UNLOCK_MINUTES * 60, 'ip': ip}
    session['csrf'] = secrets.token_urlsafe(24)
    log.warning('admin unlocked by %s from %s', who, ip)
    alert(u, 'Admin was unlocked', f'{who} unlocked happyhacks.io admin from {ip} at {_when(now)}.\n'
                                   "If this wasn't you, sign out everywhere and turn off the authenticator: "
                                   f'python -m happyhacks.accounts totp-off {who}')
    return ''


def recovery_failures(ip):
    return _recent('password_failed', ip)


def note_recovery(ok, ip):
    if ok:
        log.warning('admin recovery password used from %s', ip)
        alert(None, 'Admin recovery password was used',
              f'Someone signed in to happyhacks.io admin with ADMIN_PASSWORD from {ip} at {_when(time.time())}.\n'
              'Recovery is on (ADMIN_RECOVERY=1 in .env). Turn it off again as soon as you are back in.')
    else:
        _event('password_failed', ip)


def _who(u):
    return (u.get('email') or u.get('phone') or u.get('name') or u['id']) if u else 'admin password'


def _when(t):
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t))


sent = []   # tests read this


def alert(u, subject, body):
    """Email ADMIN_ALERT_EMAIL and the administrator concerned. Never raises, never slows the page down."""
    to = [a.strip() for a in os.environ.get('ADMIN_ALERT_EMAIL', '').split(',') if '@' in a]
    if u and u.get('email') and u['email'] not in to:
        to.append(u['email'])
    if not to:
        log.warning('admin alert (no ADMIN_ALERT_EMAIL): %s', subject)
        return
    sent.append({'to': to, 'subject': subject, 'body': body})
    del sent[:-50]

    def go():
        from . import notify
        for addr in to:
            try:
                notify.send_email(addr, f'[Happy Hacks] {subject}', body, kind='alerts')
            except Exception as e:   # noqa: BLE001 - an alert must never break anything
                log.error('admin alert to %s failed: %s', addr, e)
    threading.Thread(target=go, daemon=True).start()
