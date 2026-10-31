"""/admin: run the deploy and watch its output.

Two ways in: a Happy Hacks account with the admin role (python -m happyhacks.accounts admin <email>, or ADMIN_CONTACTS),
signed in the normal way; or ADMIN_PASSWORD from .env, kept as a backup (for example if email sign-in is down).
The admin role is Happy Hacks-only: apps never see it."""
import hmac
import os
import secrets
import time
from functools import wraps

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from . import selfupdate

bp = Blueprint('admin', __name__)

SESSION_HOURS = 12
_failures = {}   # ip -> [timestamps]; per worker, enough to slow down password guessing


def _password():
    return os.environ.get('ADMIN_PASSWORD', '')


def _client_ip():
    return request.remote_addr or '?'   # ProxyFix makes this the visitor's address behind nginx


def _locked(ip):
    now = time.time()
    recent = [t for t in _failures.get(ip, []) if now - t < 900]
    _failures[ip] = recent
    return len(recent) >= 5


def _password_session():
    return bool(session.get('admin')) and time.time() - session.get('at', 0) < SESSION_HOURS * 3600


def _account_admin():
    from .account_web import current_user
    u = current_user()
    return u if u and u.get('role') == 'admin' else None


def _signed_in():
    return _password_session() or bool(_account_admin())


def _who():
    u = _account_admin()
    return u['name'] if u else 'admin password'


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not _signed_in():
            if request.path.startswith('/admin/api/'):
                return jsonify(error='Please sign in again.'), 401
            return redirect(url_for('admin.login'))
        if request.method == 'POST' and not hmac.compare_digest(
                request.headers.get('X-CSRF-Token', ''), session.get('csrf', '')):
            return jsonify(error='This page is out of date. Reload it and try again.'), 400
        return view(*a, **kw)
    return wrapped


@bp.route('/admin/login', methods=['GET', 'POST'])
def login():
    from .account_web import current_user
    if request.method == 'GET' and _signed_in():
        return redirect(url_for('admin.dashboard'))
    u = current_user()
    not_admin = u['name'] if u and u.get('role') != 'admin' else None
    error = None
    if request.method == 'POST' and not _password():
        error = 'The admin password is turned off (ADMIN_PASSWORD is empty in .env). Sign in with an administrator account.'
    elif request.method == 'POST':
        ip = _client_ip()
        if _locked(ip):
            error = 'Too many tries. Wait 15 minutes and try again.'
        elif hmac.compare_digest(request.form.get('password', '').encode(), _password().encode()):
            _failures.pop(ip, None)
            session.clear()
            session.permanent = True
            session.update(admin=True, at=time.time(), csrf=secrets.token_urlsafe(24))
            return redirect(url_for('admin.dashboard'))
        else:
            _failures.setdefault(ip, []).append(time.time())
            error = 'That password is not right.'
    return render_template('admin_login.html', error=error, not_admin=not_admin, password_on=bool(_password())), \
        (429 if error and 'Too many' in error else 200)


@bp.post('/admin/logout')
def logout():
    """Signs out of /admin; an account administrator is signed out of their Happy Hacks account too."""
    from . import accounts
    from .account_web import SESSION_COOKIE
    if request.form.get('csrf') and hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '')) and _account_admin():
        accounts.end_session(request.cookies.get(SESSION_COOKIE))
    session.clear()
    resp = redirect(url_for('admin.login'))
    resp.delete_cookie(SESSION_COOKIE, path='/')
    return resp


@bp.get('/admin')
@login_required
def dashboard():
    from .account_web import csrf_token
    return render_template('admin.html', csrf=csrf_token(), who=_who())


@bp.get('/admin/api/updates')
@login_required
def updates():
    fetch = request.args.get('fetch', '1') != '0'
    st = selfupdate.status(10 ** 12)
    st.pop('log', None)
    return jsonify({**selfupdate.version(fetch=fetch), **st})


@bp.post('/admin/api/updates')
@login_required
def update_run():
    try:
        pid = selfupdate.start(_who())
    except selfupdate.UpdateError as e:
        return jsonify(error=str(e)), 409
    return jsonify(ok=True, pid=pid)


@bp.get('/admin/api/updates/log')
@login_required
def update_log():
    return jsonify(selfupdate.status(request.args.get('from', 0, type=int)))


@bp.after_request
def no_store(resp):
    if request.path.startswith('/admin'):
        resp.headers['Cache-Control'] = 'no-store'
        resp.headers['X-Robots-Tag'] = 'noindex'
    return resp

