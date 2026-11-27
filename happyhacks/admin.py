"""/admin: run the deploy and watch its output.

Hidden: every /admin address answers 404 until it's unlocked (see adminlock.py). Ways in:
  - a Happy Hacks account with the admin role (python -m happyhacks.accounts admin <email>, or ADMIN_CONTACTS) that
    unlocks admin on /account with a code from its authenticator app
  - recovery only: ADMIN_PASSWORD, accepted on /admin/login only while ADMIN_RECOVERY=1 is also in .env
The admin role is Happy Hacks-only: apps never see it."""
import hmac
import os
import secrets
import time
from functools import wraps

from flask import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for

from . import adminlock, selfupdate

bp = Blueprint('admin', __name__)

SESSION_HOURS = 12


def _password():
    return os.environ.get('ADMIN_PASSWORD', '')


def _client_ip():
    return request.remote_addr or '?'   # ProxyFix makes this the visitor's address behind nginx


def _password_session():
    """Signed in with the recovery password (only counts while ADMIN_RECOVERY is on)."""
    return adminlock.recovery_on() and bool(session.get('admin')) and \
        time.time() - session.get('at', 0) < SESSION_HOURS * 3600


def _account_admin():
    """The signed-in administrator, if they've unlocked admin in this browser."""
    from .account_web import current_user
    u = current_user()
    return u if u and u.get('role') == 'admin' and adminlock.unlocked() else None


@bp.before_request
def hidden():
    """/admin doesn't exist until it's unlocked. An administrator whose unlock ran out is sent back to unlock it;
    anyone else gets the site's ordinary 404."""
    if _password_session():
        return None
    if adminlock.unlocked():
        adminlock.touch()
        return None
    if request.path == '/admin/login' and adminlock.recovery_on():
        return None
    if adminlock.expired_for_admin():
        if request.path.startswith('/admin/api/'):
            return jsonify(error='Admin locked itself after 30 minutes. Unlock it again from your account page.'), 401
        return redirect(url_for('account.home', admin='locked'))
    abort(404)


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
    """Recovery sign-in with ADMIN_PASSWORD (reachable only while ADMIN_RECOVERY=1)."""
    if request.method == 'GET' and _signed_in():
        return redirect(url_for('admin.dashboard'))
    error = None
    if request.method == 'POST':
        ip = _client_ip()
        if adminlock.recovery_failures(ip) >= adminlock.FAILS_ALLOWED:
            error = 'Too many tries. Wait 15 minutes and try again.'
        elif hmac.compare_digest(request.form.get('password', '').encode(), _password().encode()):
            adminlock.note_recovery(True, ip)
            session.clear()
            session.permanent = True
            session.update(admin=True, at=time.time(), csrf=secrets.token_urlsafe(24))
            return redirect(url_for('admin.dashboard'))
        else:
            adminlock.note_recovery(False, ip)
            error = 'That password is not right.'
    return render_template('admin_login.html', error=error), (429 if error and 'Too many' in error else 200)


@bp.post('/admin/logout')
def logout():
    """Locks admin again (and ends a recovery sign-in). The Happy Hacks account stays signed in."""
    if request.form.get('csrf') and hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '')):
        session.pop('admin', None)
        session.pop('at', None)
        adminlock.lock()
    return redirect(url_for('account.home'))


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
    adminlock.alert(_account_admin(), f'{_who()} started a website update',
                    f'{_who()} started a happyhacks.io update from {_client_ip()} at {adminlock._when(time.time())}.')
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

