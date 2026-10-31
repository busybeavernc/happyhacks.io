"""Happy Hacks accounts: one sign-in for every Happy Hacks app. Ported from zipzip's autofill/accounts.py, keeping
only identity (who you are, how you sign in); each app keeps its own roles, plans and settings.

No passwords: sign up with a name and an email address; sign in with the 6-digit code sent there, or the link in the
message. A mobile number can be added once signed in, and then used to sign in by text.

  start(contact, name?)  -> sends a code + a link; the browser gets a "pending" cookie for this attempt
  verify(pending, code)  -> the code only works in the browser that asked for it (with its pending cookie)
  link(token)            -> the link shows the code (to type on the device that asked), or signs in directly when opened
                            in that same browser, or on this device if the person chooses to
Sessions are random tokens in an HttpOnly cookie; only their SHA-256 is stored. Codes expire in 10 minutes, 5 tries.

Keeping strangers from being spammed through the form (same rules as zipzip):
  - new accounts start with an email address; a mobile number is added (and confirmed) once signed in
  - texts go only to a number an account has already confirmed, and only US / Canadian numbers. Any other number gets
    the same "sent" answer with nothing sent, so the form never tells anyone which numbers have accounts
  - one email address (however it's written: case, "+tag", Gmail dots) or number belongs to one account only
  - per address: 5 codes an hour, 3 a day without an account (10 with one), and a growing wait between unused codes
    (30 s, 2 min, 10 min); per IP: 20 an hour; site-wide: SITE_PER_HOUR, after which sending pauses
  - bots (the hidden form box filled, or the form sent in under 1.5 s) get a decoy: a normal "sent" answer, nothing sent

    python -m happyhacks.accounts list                       accounts
    python -m happyhacks.accounts import-zipzip users.json   copy zipzip's accounts in (same ids, contacts, confirmations)
    python -m happyhacks.accounts suspend|unsuspend <email|phone|id>
"""
import hashlib
import hmac
import json
import logging
import re
import secrets
import sys
import time

from . import settings
from .sqldb import SQL

log = logging.getLogger('happyhacks.auth')

CODE_TTL = 600
CODE_TRIES = 5
SESSION_DAYS = 60
SENDS_PER_CONTACT_HOUR = 5
SENDS_PER_IP_HOUR = 20
SENDS_PER_NEW_CONTACT_DAY = 3
SENDS_PER_ACCOUNT_DAY = 10
RESEND_WAIT = (30, 120, 600)
SITE_PER_HOUR = {'sms': 200, 'email': 500}   # AUTH_SMS_PER_HOUR / AUTH_EMAIL_PER_HOUR
DECOYS_PER_IP_HOUR = 200

MYSQL = [
    """CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(24) NOT NULL PRIMARY KEY, name VARCHAR(120) NOT NULL, email VARCHAR(254) NULL, phone VARCHAR(20) NULL,
      email_verified_at DOUBLE NULL, phone_verified_at DOUBLE NULL, created_at DOUBLE NOT NULL, last_login_at DOUBLE NULL,
      suspended_at DOUBLE NULL, suspended_reason VARCHAR(500) NULL,
      UNIQUE KEY uq_email (email), UNIQUE KEY uq_phone (phone)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE TABLE IF NOT EXISTS login_codes (
      id VARCHAR(24) NOT NULL PRIMARY KEY, purpose VARCHAR(16) NOT NULL, channel VARCHAR(8) NOT NULL, target VARCHAR(254) NOT NULL,
      user_id VARCHAR(24) NULL, pending_name VARCHAR(120) NULL, code_hash CHAR(64) NOT NULL, link_hash CHAR(64) NOT NULL,
      browser_hash CHAR(64) NOT NULL, ip VARCHAR(64) NULL, created_at DOUBLE NOT NULL, expires_at DOUBLE NOT NULL,
      attempts INT NOT NULL DEFAULT 0, used_at DOUBLE NULL,
      KEY idx_link (link_hash), KEY idx_browser (browser_hash), KEY idx_target (target, created_at), KEY idx_ip (ip, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64) NOT NULL PRIMARY KEY, user_id VARCHAR(24) NOT NULL, created_at DOUBLE NOT NULL, last_seen DOUBLE NOT NULL,
      expires_at DOUBLE NOT NULL, user_agent VARCHAR(255) NULL, ip VARCHAR(64) NULL, KEY idx_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
]
SQLITE = [
    """CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, phone TEXT UNIQUE,
      email_verified_at REAL, phone_verified_at REAL, created_at REAL NOT NULL, last_login_at REAL,
      suspended_at REAL, suspended_reason TEXT)""",
    """CREATE TABLE IF NOT EXISTS login_codes (id TEXT PRIMARY KEY, purpose TEXT NOT NULL, channel TEXT NOT NULL, target TEXT NOT NULL,
      user_id TEXT, pending_name TEXT, code_hash TEXT NOT NULL, link_hash TEXT NOT NULL, browser_hash TEXT NOT NULL, ip TEXT,
      created_at REAL NOT NULL, expires_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used_at REAL)""",
    'CREATE INDEX IF NOT EXISTS idx_link ON login_codes (link_hash)',
    'CREATE INDEX IF NOT EXISTS idx_browser ON login_codes (browser_hash)',
    'CREATE INDEX IF NOT EXISTS idx_target ON login_codes (target, created_at)',
    """CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at REAL NOT NULL,
      last_seen REAL NOT NULL, expires_at REAL NOT NULL, user_agent TEXT, ip TEXT)""",
]


class AuthError(Exception):
    def __init__(self, message, status=400, **extra):
        super().__init__(message)
        self.status, self.extra = status, extra


_db = None


def db():
    global _db
    if _db is None:
        _db = SQL(MYSQL, SQLITE, 'accounts.sqlite')
    return _db


def reset():
    global _db
    _db = None


def _h(s):
    return hashlib.sha256(str(s).encode()).hexdigest()


def _id(prefix):
    return prefix + secrets.token_hex(6)


def secret_key():
    """Signs the codes. SECRET_KEY from .env (the installer generates it); inside the app, the app's own secret key."""
    k = settings.get('SECRET_KEY')
    if not k:
        from flask import current_app, has_app_context
        k = current_app.secret_key if has_app_context() else None
    if not k:
        raise RuntimeError('SECRET_KEY is not set in .env')
    return k


# ------------------------------------------------------------------ contacts
EMAIL = re.compile(r'^[^@\s]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def parse_contact(text):
    """-> ('email', 'a@b.com') or ('sms', '+19195550100'); raises AuthError."""
    t = str(text or '').strip()
    if '@' in t:
        if not EMAIL.match(t) or len(t) > 254:
            raise AuthError('That email address doesn\'t look right.')
        return 'email', t.lower()
    digits = re.sub(r'\D', '', t)
    if t.startswith('+') and 8 <= len(digits) <= 15 and not digits.startswith('1'):
        raise AuthError('Texts go to US and Canadian mobile numbers only. Use your email address.')
    if len(digits) == 11 and digits.startswith('1'):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] not in '01':
        return 'sms', '+1' + digits
    raise AuthError('Enter an email address or a 10-digit mobile number.')


def mask(channel, target):
    if channel == 'email':
        user, dom = target.split('@', 1)
        return (user[0] + '•' * max(1, min(len(user) - 1, 6)) + '@' + dom) if user else target
    return f'(•••) •••-{target[-4:]}'


def pretty_phone(p):
    d = re.sub(r'\D', '', p or '')
    return f'({d[1:4]}) {d[4:7]}-{d[7:]}' if len(d) == 11 and d[0] == '1' else (p or '')


# ------------------------------------------------------------------ users
def _user(row):
    if not row:
        return None
    return {'id': row['id'], 'name': row['name'], 'email': row.get('email'), 'phone': row.get('phone'),
            'email_verified': bool(row.get('email_verified_at')), 'phone_verified': bool(row.get('phone_verified_at')),
            'created_at': row.get('created_at'), 'last_login_at': row.get('last_login_at'),
            'suspended_at': row.get('suspended_at'), 'suspended_reason': row.get('suspended_reason')}


def get_user(user_id):
    return _user(db().run('SELECT * FROM users WHERE id=%s', (user_id,), fetch='one'))


def find_user(channel, target):
    col = 'email' if channel == 'email' else 'phone'
    return _user(db().run(f'SELECT * FROM users WHERE {col}=%s', (target,), fetch='one'))


DOTLESS = {'gmail.com', 'googlemail.com'}


def email_key(addr):
    """One inbox, however it's written: case, a "+tag", and (Gmail) dots don't make a different address."""
    user, _, dom = str(addr or '').strip().lower().partition('@')
    user = user.split('+', 1)[0]
    if dom in DOTLESS:
        user, dom = user.replace('.', ''), 'gmail.com'
    return f'{user}@{dom}'


def owner_of(channel, target):
    """The account that already has this email (written any way) or number, else None. One contact, one account."""
    exact = find_user(channel, target)
    if exact or channel != 'email':
        return exact
    key, dom = email_key(target), target.rsplit('@', 1)[-1]
    doms = DOTLESS if dom in DOTLESS else {dom}
    for d in doms:
        for r in db().run('SELECT * FROM users WHERE email LIKE %s', ('%@' + d,), fetch='all') or []:
            if email_key(r['email']) == key:
                return _user(r)
    return None


def create_user(name, channel, target):
    uid, now = _id('u'), time.time()
    db().run('INSERT INTO users (id, name, email, phone, email_verified_at, phone_verified_at, created_at, last_login_at) '
             'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
             (uid, name, target if channel == 'email' else None, target if channel == 'sms' else None,
              now if channel == 'email' else None, now if channel == 'sms' else None, now, now))
    return get_user(uid)


def update_name(user_id, name):
    nm = re.sub(r'\s+', ' ', str(name or '')).strip()[:120]
    if not nm:
        raise AuthError('Your name can\'t be empty.')
    db().run('UPDATE users SET name=%s WHERE id=%s', (nm, user_id))
    return get_user(user_id)


def remove_contact(user_id, channel):
    u = get_user(user_id)
    other = u['phone'] if channel == 'email' else u['email']
    if not other:
        raise AuthError('Keep at least one way to sign in: add the other one first.')
    col = 'email' if channel == 'email' else 'phone'
    db().run(f'UPDATE users SET {col}=NULL, {col}_verified_at=NULL WHERE id=%s', (user_id,))
    return get_user(user_id)


def set_suspended(user_id, on, reason=None):
    if on:
        db().run('UPDATE users SET suspended_at=%s, suspended_reason=%s WHERE id=%s', (time.time(), str(reason or '')[:500] or None, user_id))
        end_session(None, everywhere_for=user_id)
    else:
        db().run('UPDATE users SET suspended_at=NULL, suspended_reason=NULL WHERE id=%s', (user_id,))
    return get_user(user_id)


def public(user):
    """What an app (or the page) may see about the signed-in user."""
    if not user:
        return None
    return {k: user[k] for k in ('id', 'name', 'email', 'phone', 'email_verified', 'phone_verified')} | \
        {'phone_display': pretty_phone(user.get('phone'))}


# ------------------------------------------------------------------ codes and links
def _code_for(link_token):
    """The 6-digit code is derived from the link, so the link page can show it without the code being stored."""
    n = int.from_bytes(hmac.new(secret_key().encode(), b'code:' + link_token.encode(), hashlib.sha256).digest()[:8], 'big')
    return f'{n % 1_000_000:06d}'


def _recent(col, value, since):
    row = db().run(f"SELECT COUNT(*) AS n FROM login_codes WHERE {col}=%s AND created_at>%s AND purpose<>'decoy'", (value, since), fetch='one')
    return int(row['n'] if row else 0)


def site_limit(channel):
    key = 'AUTH_SMS_PER_HOUR' if channel == 'sms' else 'AUTH_EMAIL_PER_HOUR'
    try:
        return max(0, int(settings.get(key) or SITE_PER_HOUR[channel]))
    except ValueError:
        return SITE_PER_HOUR[channel]


def site_sends(channel, since):
    row = db().run("SELECT COUNT(*) AS n FROM login_codes WHERE channel=%s AND created_at>%s AND purpose<>'decoy'", (channel, since), fetch='one')
    return int(row['n'] if row else 0)


def _resend_wait(target, now):
    rows = db().run("SELECT created_at, used_at FROM login_codes WHERE target=%s AND created_at>%s AND purpose<>'decoy' ORDER BY created_at DESC",
                    (target, now - 3600), fetch='all')
    if not rows or rows[0]['used_at']:
        return 0
    rows = [r for r in rows if not r['used_at']]
    gap = RESEND_WAIT[min(len(rows), len(RESEND_WAIT)) - 1]
    return max(0, int(rows[0]['created_at'] + gap - now + 0.999))


def _wait_text(sec):
    return f'{sec} seconds' if sec < 90 else f'{round(sec / 60)} minutes'


def decoy(contact, ip=None):
    """A bot (or a number no account has confirmed): answer exactly like a real send, send nothing."""
    try:
        channel, target = parse_contact(contact)
    except AuthError:
        channel, target = 'email', 'someone@example.com'
    pending, now = secrets.token_urlsafe(24), time.time()
    kept = db().run("SELECT COUNT(*) AS n FROM login_codes WHERE ip=%s AND created_at>%s AND purpose='decoy'", (ip, now - 3600), fetch='one') if ip else None
    if not kept or int(kept['n']) < DECOYS_PER_IP_HOUR:
        db().run('INSERT INTO login_codes (id, purpose, channel, target, user_id, pending_name, code_hash, link_hash, browser_hash, ip, created_at, expires_at) '
                 'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                 (_id('c'), 'decoy', channel, target[:254], None, None, _h(secrets.token_hex(16)), _h(secrets.token_hex(16)), _h(pending), ip, now, now + CODE_TTL))
    existing = owner_of(channel, target)
    return pending, {'channel': channel, 'target': target, 'masked': mask(channel, target),
                     'purpose': 'login' if existing or channel == 'sms' else 'signup', 'decoy': True}


def start(contact, name=None, ip=None, purpose=None, user_id=None):
    """Begin sign-in / sign-up / adding a contact. Returns (pending_token, info); `send` delivers it.
    Raises AuthError(need_name=True) when the address has no account and no name was given."""
    from . import notify
    channel, target = parse_contact(contact)
    existing = owner_of(channel, target)
    if channel == 'sms' and purpose not in ('add_email', 'add_phone') and not (existing and existing.get('phone_verified')):
        return decoy(contact, ip)
    if purpose in ('add_email', 'add_phone'):
        other = owner_of(channel, target)
        if other and other['id'] != user_id:
            raise AuthError('That is already used by another account. Each email address and mobile number can belong to one account only.', 409)
    elif existing:
        purpose, user_id = 'login', existing['id']
    else:
        name = re.sub(r'\s+', ' ', str(name or '')).strip()[:120]
        if not name:
            raise AuthError('New here? Enter your name to create your free account.', need_name=True)
        purpose = 'signup'
    if channel == 'sms' and not notify.sms_ready():
        raise AuthError('Signing in by text message isn\'t available yet. Use your email address.')
    if channel == 'email' and not notify.email_ready():
        raise AuthError('Signing in by email isn\'t available yet.')
    now = time.time()
    hour, day = now - 3600, now - 86400
    per_day = SENDS_PER_ACCOUNT_DAY if existing or purpose in ('add_email', 'add_phone') else SENDS_PER_NEW_CONTACT_DAY
    if _recent('target', target, hour) >= SENDS_PER_CONTACT_HOUR or _recent('target', target, day) >= per_day \
            or (ip and _recent('ip', ip, hour) >= SENDS_PER_IP_HOUR):
        raise AuthError('Too many codes were requested for this. Try again later.', 429)
    wait = _resend_wait(target, now)
    if wait:
        raise AuthError(f'A code was just sent. Wait {_wait_text(wait)} before asking for another, and check your spam folder.', 429, wait=wait)
    if site_sends(channel, hour) >= site_limit(channel):
        log.warning('sign-in %s codes paused: %s sent in the last hour', channel, site_limit(channel))
        raise AuthError('Sign-in codes are paused for a few minutes. Try again shortly.', 503)
    link_token, pending = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    code = _code_for(link_token)
    rid = _id('c')
    db().run('INSERT INTO login_codes (id, purpose, channel, target, user_id, pending_name, code_hash, link_hash, browser_hash, ip, created_at, expires_at) '
             'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
             (rid, purpose, channel, target, user_id, name if purpose == 'signup' else None, _code_hash(rid, code), _h(link_token),
              _h(pending), ip, now, now + CODE_TTL))
    return pending, {'channel': channel, 'target': target, 'masked': mask(channel, target), 'purpose': purpose, 'code': code,
                     'link_token': link_token, 'name': (existing or {}).get('name') if purpose == 'login' else None}


def send(info, base_url, app_name=None, app_id=None):
    if info.get('decoy'):
        return
    from . import notify
    # &app=: the link page wears that app's look even when opened in another browser (registered apps only)
    link = f"{base_url.rstrip('/')}/account/link?t={info['link_token']}" + (f'&app={app_id}' if app_id else '')
    notify.sign_in_message(info['channel'], info['target'], info['code'], link, info['purpose'], info.get('name'), app_name)


def _complete(row):
    """Code accepted: mark used, create/verify the account. Returns (user, purpose)."""
    now = time.time()
    if db().run('UPDATE login_codes SET used_at=%s WHERE id=%s AND used_at IS NULL', (now, row['id'])) == 0:
        raise AuthError('That code was already used. Request a new one.')
    col = 'email' if row['channel'] == 'email' else 'phone'
    if row.get('user_id') and (get_user(row['user_id']) or {}).get('suspended_at'):
        raise AuthError('This account is suspended. Contact Happy Hacks support.', 403)
    if row['purpose'] == 'signup':
        existing = owner_of(row['channel'], row['target'])
        user = existing or create_user(row['pending_name'] or 'New user', row['channel'], row['target'])
    elif row['purpose'] in ('add_email', 'add_phone'):
        other = owner_of(row['channel'], row['target'])
        if other and other['id'] != row['user_id']:
            raise AuthError('That is already used by another account. Each email address and mobile number can belong to one account only.', 409)
        try:
            db().run(f'UPDATE users SET {col}=%s, {col}_verified_at=%s WHERE id=%s', (row['target'], now, row['user_id']))
        except Exception as e:   # noqa: BLE001 - the unique index caught a race
            raise AuthError('That is already used by another account. Each email address and mobile number can belong to one account only.', 409) from e
        user = get_user(row['user_id'])
    else:
        user = get_user(row['user_id'])
        if not user:
            raise AuthError('That account no longer exists.')
        db().run(f'UPDATE users SET last_login_at=%s, {col}_verified_at=COALESCE({col}_verified_at, %s) WHERE id=%s', (now, now, user['id']))
        user = get_user(user['id'])
    return user, row['purpose']


def verify(pending, code, purposes=('login', 'signup')):
    code = re.sub(r'\D', '', str(code or ''))
    if not pending:
        raise AuthError('This browser didn\'t start a sign-in. Enter your email or number again.')
    rows = db().run('SELECT * FROM login_codes WHERE browser_hash=%s AND used_at IS NULL ORDER BY created_at DESC', (_h(pending),), fetch='all')
    row = next((r for r in rows if r['purpose'] in purposes or r['purpose'] == 'decoy'), None)
    if not row or row['expires_at'] < time.time():
        raise AuthError('That code has expired. Request a new one.')
    if row['attempts'] >= CODE_TRIES:
        raise AuthError('Too many wrong codes. Request a new one.', 429)
    db().run('UPDATE login_codes SET attempts=attempts+1 WHERE id=%s', (row['id'],))
    rows = db().run('SELECT * FROM login_codes WHERE browser_hash=%s AND used_at IS NULL AND expires_at>%s', (_h(pending), time.time()), fetch='all')
    for r in (r for r in rows if r['purpose'] in purposes):
        if len(code) == 6 and _code_matches(r, code):
            return _complete(r)
    left = CODE_TRIES - row['attempts'] - 1
    raise AuthError('That code isn\'t right.' + (f' {left} tries left.' if left > 0 else ' Request a new one.'))


def _code_matches(row, code):
    return hmac.compare_digest(row['code_hash'], _code_hash(row['id'], code))


def _code_hash(row_id, code):
    return _h(f'{code}:{row_id}:{secret_key()}')


def link_info(link_token):
    row = db().run('SELECT * FROM login_codes WHERE link_hash=%s', (_h(link_token),), fetch='one')
    if not row or row['used_at'] or row['expires_at'] < time.time() or row['purpose'] == 'decoy':
        return None
    return row


def link_complete(link_token):
    row = link_info(link_token)
    if not row:
        raise AuthError('This link has expired or was already used. Request a new code.')
    return _complete(row)


def code_for_link(link_token):
    return _code_for(link_token)


def pending_matches(pending, row):
    return bool(pending) and hmac.compare_digest(_h(pending), row['browser_hash'])


# ------------------------------------------------------------------ sessions
def new_session(user_id, user_agent=None, ip=None):
    token = secrets.token_urlsafe(32)
    now = time.time()
    db().run('INSERT INTO sessions (token_hash, user_id, created_at, last_seen, expires_at, user_agent, ip) VALUES (%s,%s,%s,%s,%s,%s,%s)',
             (_h(token), user_id, now, now, now + SESSION_DAYS * 86400, (user_agent or '')[:255], ip))
    return token


def session_user(token):
    if not token:
        return None
    row = db().run('SELECT * FROM sessions WHERE token_hash=%s', (_h(token),), fetch='one')
    now = time.time()
    if not row or row['expires_at'] < now:
        return None
    if now - row['last_seen'] > 3600:
        db().run('UPDATE sessions SET last_seen=%s, expires_at=%s WHERE token_hash=%s', (now, now + SESSION_DAYS * 86400, row['token_hash']))
    user = get_user(row['user_id'])
    return None if not user or user.get('suspended_at') else user


def end_session(token, everywhere_for=None):
    if everywhere_for:
        db().run('DELETE FROM sessions WHERE user_id=%s', (everywhere_for,))
    elif token:
        db().run('DELETE FROM sessions WHERE token_hash=%s', (_h(token),))


def sessions_of(user_id):
    rows = db().run('SELECT created_at, last_seen, expires_at, user_agent, ip FROM sessions WHERE user_id=%s ORDER BY last_seen DESC', (user_id,), fetch='all')
    now = time.time()
    return [r for r in rows if r['expires_at'] > now]


# ------------------------------------------------------------------ bringing in zipzip's accounts
def import_users(rows):
    """Copy accounts from an app (zipzip's `python -m autofill.accounts export`) keeping their ids, so each app's own
    data stays theirs. An account whose email or number already belongs to a Happy Hacks account is skipped and reported.
    Returns {'added', 'same', 'skipped': [(id, reason)]}."""
    added, same, skipped = 0, 0, []
    for r in rows:
        uid = str(r.get('id') or '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{4,24}', uid):
            skipped.append((uid, 'bad id'))
            continue
        if get_user(uid):
            same += 1
            continue
        email = (r.get('email') or '').strip().lower() or None
        phone = (r.get('phone') or '').strip() or None
        if not email and not phone:
            skipped.append((uid, 'no email or phone'))
            continue
        clash = (email and owner_of('email', email)) or (phone and find_user('sms', phone))
        if clash:
            skipped.append((uid, f"{email or phone} already belongs to Happy Hacks account {clash['id']}"))
            continue
        now = time.time()
        db().run('INSERT INTO users (id, name, email, phone, email_verified_at, phone_verified_at, created_at, last_login_at) '
                 'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                 (uid, (str(r.get('name') or '').strip() or 'Happy Hacks user')[:120], email, phone,
                  (r.get('email_verified_at') or (now if r.get('email_verified') else None)) if email else None,
                  (r.get('phone_verified_at') or (now if r.get('phone_verified') else None)) if phone else None,
                  r.get('created_at') or now, r.get('last_login_at')))
        added += 1
    return {'added': added, 'same': same, 'skipped': skipped}


def _main(argv):
    cmd = argv[0] if argv else 'list'
    if cmd == 'list':
        for r in db().run('SELECT id, name, email, phone, created_at, suspended_at FROM users ORDER BY created_at', fetch='all'):
            print(f"{r['id']}  {r['name']}  {r['email'] or ''}  {r['phone'] or ''}{'  (suspended)' if r['suspended_at'] else ''}")
        return 0
    if cmd == 'check':
        n = db().run('SELECT COUNT(*) AS n FROM users', fetch='one')['n']
        where = 'MySQL ' + settings.db_settings()['database'] if settings.db_settings() else 'SQLite in ' + settings.data_dir()
        print(f'Accounts database OK ({where}): {n} account(s).')
        return 0
    if cmd == 'import-zipzip' and len(argv) > 1:
        with open(argv[1], encoding='utf-8') as fh:
            data = json.load(fh)
        res = import_users(data.get('users', data) if isinstance(data, dict) else data)
        print(f"Added {res['added']}, already here {res['same']}, skipped {len(res['skipped'])}.")
        for uid, why in res['skipped']:
            print(f'  skipped {uid}: {why}')
        return 0
    if cmd in ('suspend', 'unsuspend') and len(argv) > 1:
        u = get_user(argv[1])
        if not u:
            try:
                u = owner_of(*parse_contact(argv[1]))
            except AuthError:
                u = None
        if not u:
            print('No such account.')
            return 1
        set_suspended(u['id'], cmd == 'suspend', ' '.join(argv[2:]) or None)
        print(f"{u['name']}: {'suspended (signed out everywhere)' if cmd == 'suspend' else 'active again'}.")
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    import os
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(settings.ROOT, '.env'))
    except ImportError:
        pass
    sys.exit(_main(sys.argv[1:]))
