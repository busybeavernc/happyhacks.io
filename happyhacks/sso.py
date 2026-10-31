"""Sign in with Happy Hacks: how ZipZip, Doppleganger and future apps use one Happy Hacks account.

The standard authorization-code flow with PKCE (as in OAuth 2.0 / OpenID Connect, kept small):
  1. The app sends the browser to  /account/authorize?client_id=..&redirect_uri=..&state=..&code_challenge=..&code_challenge_method=S256
  2. Happy Hacks signs the person in (instantly if they already are) and sends the browser back to
     redirect_uri?code=..&state=..   The code works once, for 2 minutes, only for that app and that redirect_uri.
  3. The app's server POSTs  /account/token  {client_id, client_secret, code, redirect_uri, code_verifier}
     and gets  {"user": {id, name, email, email_verified, phone, phone_verified}}.
  The app then keeps its own session (and its own roles, plans and data) for that user id.

Apps are registered in .env (the secret itself lives only in the app's .env; Happy Hacks keeps its SHA-256):
  HH_CLIENTS=zipzip
  HH_CLIENT_ZIPZIP_NAME=ZipZip
  HH_CLIENT_ZIPZIP_SECRET_SHA256=<hex>
  HH_CLIENT_ZIPZIP_REDIRECT_URIS=https://zipzip.happyhacks.io/auth/happyhacks/callback

    python -m happyhacks.sso add <id> "<Name>" <redirect_uri> [more redirect uris]
        registers an app in .env and prints the settings to put in that app's .env
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import sys
import time
from urllib.parse import urlsplit

from . import accounts, settings
from .sqldb import SQL

CODE_TTL = 120

MYSQL = ["""CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash CHAR(64) NOT NULL PRIMARY KEY, client_id VARCHAR(40) NOT NULL, user_id VARCHAR(24) NOT NULL, redirect_uri VARCHAR(500) NOT NULL,
  challenge VARCHAR(128) NOT NULL, created_at DOUBLE NOT NULL, expires_at DOUBLE NOT NULL, used_at DOUBLE NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""]
SQLITE = ["""CREATE TABLE IF NOT EXISTS auth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL)"""]


class SSOError(Exception):
    def __init__(self, message, error='invalid_request', status=400):
        super().__init__(message)
        self.error, self.status = error, status


_db = None


def db():
    global _db
    if _db is None:
        _db = SQL(MYSQL, SQLITE, 'accounts.sqlite')
    return _db


def reset():
    global _db
    _db = None


ID = re.compile(r'^[a-z][a-z0-9-]{1,38}$')


def _env_key(cid):
    return 'HH_CLIENT_' + cid.upper().replace('-', '_')


def clients():
    out = {}
    for cid in [c.strip().lower() for c in str(settings.get('HH_CLIENTS', '')).split(',') if c.strip()]:
        if not ID.match(cid):
            continue
        k = _env_key(cid)
        uris = [u for u in re.split(r'[\s,]+', settings.get(k + '_REDIRECT_URIS', '') or '') if u]
        secret_hash = (settings.get(k + '_SECRET_SHA256') or '').lower()
        if uris and re.fullmatch(r'[0-9a-f]{64}', secret_hash):
            out[cid] = {'id': cid, 'name': settings.get(k + '_NAME') or cid, 'redirect_uris': uris, 'secret_sha256': secret_hash}
    return out


def client(cid):
    return clients().get(str(cid or '').lower())


def check_authorize(args):
    """Validate an /account/authorize request. Returns the client and the cleaned parameters; raises SSOError.
    An unknown client or redirect_uri is shown as an error page (never redirected to)."""
    c = client(args.get('client_id'))
    if not c:
        raise SSOError('This app isn\'t registered with Happy Hacks.', 'unauthorized_client')
    uri = args.get('redirect_uri') or ''
    if uri not in c['redirect_uris']:
        raise SSOError('This app asked to return to an address Happy Hacks doesn\'t know.', 'invalid_request')
    if args.get('response_type', 'code') != 'code':
        raise SSOError('Unsupported response_type.', 'unsupported_response_type')
    challenge = args.get('code_challenge') or ''
    if args.get('code_challenge_method') != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', challenge):
        raise SSOError('The app\'s sign-in request is missing its PKCE challenge (S256).', 'invalid_request')
    state = args.get('state') or ''
    if len(state) > 500:
        raise SSOError('state is too long.')
    return c, {'redirect_uri': uri, 'challenge': challenge, 'state': state}


def issue_code(cid, user_id, redirect_uri, challenge):
    code = secrets.token_urlsafe(32)
    now = time.time()
    db().run('INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, challenge, created_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)',
             (hashlib.sha256(code.encode()).hexdigest(), cid, user_id, redirect_uri, challenge, now, now + CODE_TTL))
    db().run('DELETE FROM auth_codes WHERE expires_at<%s', (now - 86400,))
    return code


def _pkce(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def exchange(cid, secret, code, redirect_uri, verifier):
    """The app's server trades the code for who signed in. Returns accounts.public(user)."""
    c = client(cid)
    if not c or not secret or not hmac.compare_digest(hashlib.sha256(str(secret).encode()).hexdigest(), c['secret_sha256']):
        raise SSOError('Unknown app or wrong client secret.', 'invalid_client', 401)
    if not code or not verifier or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier):
        raise SSOError('code and code_verifier are required.', 'invalid_request')
    h = hashlib.sha256(str(code).encode()).hexdigest()
    row = db().run('SELECT * FROM auth_codes WHERE code_hash=%s', (h,), fetch='one')
    now = time.time()
    if not row or row['client_id'] != c['id'] or row['used_at'] or row['expires_at'] < now:
        raise SSOError('The sign-in code is invalid, expired or already used.', 'invalid_grant')
    if db().run('UPDATE auth_codes SET used_at=%s WHERE code_hash=%s AND used_at IS NULL', (now, h)) == 0:
        raise SSOError('The sign-in code was already used.', 'invalid_grant')
    if row['redirect_uri'] != redirect_uri:
        raise SSOError('redirect_uri does not match the sign-in request.', 'invalid_grant')
    if not hmac.compare_digest(_pkce(verifier), row['challenge']):
        raise SSOError('code_verifier does not match the sign-in request.', 'invalid_grant')
    user = accounts.get_user(row['user_id'])
    if not user or user.get('suspended_at'):
        raise SSOError('This account can\'t sign in.', 'invalid_grant')
    return accounts.public(user)


def safe_return(url):
    """A sign-out "return_to" is allowed only back to a registered app's site."""
    try:
        p = urlsplit(url or '')
    except ValueError:
        return None
    if p.scheme not in ('https', 'http') or not p.netloc:
        return None
    for c in clients().values():
        for u in c['redirect_uris']:
            q = urlsplit(u)
            if (q.scheme, q.netloc) == (p.scheme, p.netloc):
                return url
    return None


def _main(argv):
    if len(argv) < 4 or argv[0] != 'add':
        print(__doc__)
        return 2
    cid, name, uris = argv[1].lower(), argv[2], argv[3:]
    if not ID.match(cid):
        print('The id must be lowercase letters, numbers and dashes (like "zipzip").')
        return 1
    for u in uris:
        p = urlsplit(u)
        if p.scheme != 'https' and p.hostname not in ('localhost', '127.0.0.1'):
            print(f'{u}: redirect addresses must be https (http only for localhost).')
            return 1
    secret = secrets.token_urlsafe(32)
    env_path = os.path.join(settings.ROOT, '.env')
    try:
        with open(env_path, encoding='utf-8') as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        lines = []
    k = _env_key(cid)
    lines = [ln for ln in lines if not ln.startswith(k + '_')]
    current = []
    for ln in lines:
        if ln.startswith('HH_CLIENTS='):
            current = [c.strip() for c in ln.split('=', 1)[1].split(',') if c.strip()]
    lines = [ln for ln in lines if not ln.startswith('HH_CLIENTS=')]
    lines += [f"HH_CLIENTS={','.join(dict.fromkeys(current + [cid]))}", f'{k}_NAME={name}',
              f'{k}_SECRET_SHA256={hashlib.sha256(secret.encode()).hexdigest()}', f"{k}_REDIRECT_URIS={' '.join(uris)}"]
    with open(env_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')
    os.chmod(env_path, 0o600)
    print(f'Registered {name} ({cid}) in {env_path}. Restart Happy Hacks:  sudo supervisorctl restart happyhacks\n')
    print(f"Put these in {name}'s .env (the secret is shown only now):\n")
    print(f'    HAPPYHACKS_URL={settings.public_url()}')
    print(f'    HAPPYHACKS_CLIENT_ID={cid}')
    print(f'    HAPPYHACKS_CLIENT_SECRET={secret}')
    return 0


if __name__ == '__main__':
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(settings.ROOT, '.env'))
    except ImportError:
        pass
    sys.exit(_main(sys.argv[1:]))
