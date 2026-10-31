"""/admin: sign in with ADMIN_PASSWORD (from .env), then run the deploy and watch its output."""
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


def _signed_in():
    return session.get('admin') and time.time() - session.get('at', 0) < SESSION_HOURS * 3600


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
    if not _password():
        return render_template('admin_login.html', error='Admin is turned off: set ADMIN_PASSWORD in .env and restart.', disabled=True), 503
    error = None
    if request.method == 'POST':
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
    return render_template('admin_login.html', error=error), (429 if error and 'Too many' in error else 200)


@bp.post('/admin/logout')
def logout():
    session.clear()
    return redirect(url_for('admin.login'))


@bp.get('/admin')
@login_required
def dashboard():
    return render_template('admin.html', csrf=session['csrf'])


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
        pid = selfupdate.start('admin')
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

