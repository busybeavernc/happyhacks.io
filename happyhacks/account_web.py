"""happyhacks.io/account: create an account, sign in, manage it, and "Sign in with Happy Hacks" for the apps.

Pages (server-rendered forms; they work without JavaScript):
  GET|POST /account/signin           email or mobile (+ name when new) -> a code and a link are sent
  GET|POST /account/code             enter the 6-digit code
  GET|POST /account/link?t=          the link in the message: shows the code, or signs this browser in
  GET      /account                  your account: name, email, mobile, devices, apps
  POST     /account/name | /account/contact | /account/contact/verify | /account/contact/remove
  POST     /account/signout          {everywhere?}
  GET      /account/signout?return_to=   for apps: sign out of Happy Hacks and go back to the app
For apps (happyhacks/sso.py):
  GET      /account/authorize        start "Sign in with Happy Hacks"
  POST     /account/token            the app's server trades the code for the user
"""
import hmac
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit, parse_qs

from flask import (Blueprint, current_app, g, jsonify, make_response, redirect, render_template, request, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import accounts, sso, themes
from .products import PRODUCTS

bp = Blueprint('account', __name__, url_prefix='/account')

SESSION_COOKIE, PENDING_COOKIE = 'hh_session', 'hh_pending'
log = __import__('logging').getLogger('happyhacks.auth')


# ------------------------------------------------------------------ helpers
def _secure():
    return bool(current_app.config.get('SESSION_COOKIE_SECURE'))


def _set_cookie(resp, name, value, max_age):
    resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=_secure(), samesite='Lax', path='/')


def current_user():
    """The signed-in Happy Hacks account for this request (cached), or None. A database outage reads as signed out."""
    if 'hh_user' not in g:
        tok = request.cookies.get(SESSION_COOKIE)
        try:
            g.hh_user = accounts.session_user(tok) if tok else None
        except Exception as e:   # noqa: BLE001
            log.error('session check failed: %s', e)
            g.hh_user = None
    return g.hh_user


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(24)
    return session['csrf']


def _check_csrf():
    sent = request.form.get('csrf', '')
    if not sent or not hmac.compare_digest(sent, session.get('csrf', '')):
        raise accounts.AuthError('This page was open too long or in another tab. Please try again.', 400)


def _form_stamp():
    return URLSafeTimedSerializer(current_app.secret_key, salt='hh-form').dumps('f')


def _looks_like_bot():
    """The form has a box people never see (bots fill every box) and a signed time it was shown: no person types an
    address and taps Send in under a second and a half."""
    if (request.form.get('website') or '').strip():
        return True
    try:
        _, shown = URLSafeTimedSerializer(current_app.secret_key, salt='hh-form').loads(
            request.form.get('ts', ''), max_age=86400, return_timestamp=True)
    except (BadSignature, SignatureExpired):
        return True
    return time.time() - shown.timestamp() < 1.5


def _safe_next(n):
    n = str(n or '')
    if n.startswith('/') and not n.startswith('//') and '\\' not in n and len(n) < 2000:
        return n
    return None


def _flow_client_id():
    """The registered app this sign-in is on its way to: from the authorize request it started with, or (on the link
    in a message, maybe opened in another browser) the ?app= the link carries. Only registered apps count."""
    n = session.get('a_next') or ''
    if n.startswith('/account/authorize'):
        cid = (parse_qs(urlsplit(n).query).get('client_id') or [''])[0]
    elif request.endpoint == 'account.link':   # only the link from a message carries ?app=
        cid = request.args.get('app') or ''
    else:
        cid = ''
    return cid if sso.client(cid) else None


def _client_for_next(n=None):
    """When signing in on the way to an app, its name (for "Sign in to continue to ZipZip")."""
    c = sso.client(_flow_client_id())
    return c['name'] if c else None


def _base_url():
    from . import settings
    return settings.get('PUBLIC_URL') or request.url_root


def _signed_in(user, resp):
    tok = accounts.new_session(user['id'], request.headers.get('User-Agent'), request.remote_addr)
    _set_cookie(resp, SESSION_COOKIE, tok, accounts.SESSION_DAYS * 86400)
    resp.delete_cookie(PENDING_COOKIE, path='/')
    for k in ('a_contact', 'a_name', 'a_masked', 'a_channel', 'a_purpose'):
        session.pop(k, None)
    return resp


def _after_sign_in(new=False):
    n = _safe_next(session.pop('a_next', None))
    return redirect(n or url_for('account.home', welcome=1 if new else None), 303)


def _page(template, status=200, cid=None, **kw):
    """A page of the sign-in flow. On the way to a registered app it wears that app's theme (happyhacks/themes)."""
    theme = themes.for_client(cid or _flow_client_id())
    if theme and template != 'account/home.html':
        kw.update(theme=theme, site_name=theme['name'])
    resp = make_response(render_template(template, **kw), status)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp


@bp.app_context_processor
def inject():
    return {'hh_user': current_user(), 'csrf_token': csrf_token}


# ------------------------------------------------------------------ sign in / sign up
@bp.get('/signin')
def signin():
    n = _safe_next(request.args.get('next'))
    if n:
        session['a_next'] = n
    elif not request.args.get('keep'):
        session.pop('a_next', None)   # a plain visit: don't carry an old "continue to" along
    if current_user():
        return _after_sign_in()
    mode = 'signup' if request.args.get('new') else 'signin'
    return _page('account/signin.html', mode=mode, stamp=_form_stamp(), app_name=_client_for_next(session.get('a_next')),
                 contact='', name='', need_name=False, error=None)


@bp.post('/signin')
def signin_post():
    _check_csrf()
    contact = (request.form.get('contact') or '').strip()
    resend = request.form.get('resend') == '1'
    name = (request.form.get('name') or '').strip() or (session.get('a_name') if resend else '')
    app_name = _client_for_next(session.get('a_next'))
    mode = request.form.get('mode') or 'signin'

    def again(error, need_name=False, status=400):
        return _page('account/signin.html', status, mode=mode, stamp=_form_stamp(), app_name=app_name, contact=contact, name=name,
                     need_name=need_name, error=error)

    if not resend and _looks_like_bot():
        time.sleep(0.6 + secrets.randbelow(800) / 1000)
        pending, info = accounts.decoy(contact, ip=request.remote_addr)
        log.info('sign-in form: bot answered with a decoy (%s)', request.remote_addr)
    else:
        try:
            pending, info = accounts.start(contact, name, ip=request.remote_addr)
        except accounts.AuthError as e:
            if e.extra.get('need_name'):
                msg = None if name else ('Welcome! Tell us your name to create your free account.' if mode == 'signup'
                                         else 'We couldn\'t find an account for that. Check it, or add your name to create a free one.')
                return again(msg, need_name=True, status=200 if not name else 400)
            return again(str(e), status=e.status)
        try:
            accounts.send(info, _base_url(), app_name, _flow_client_id())
        except Exception as e:   # noqa: BLE001
            return again(str(e) if e.__class__.__name__ == 'SendError' else 'The code could not be sent. Try again.', status=502)
    session.update(a_contact=contact, a_name=name, a_masked=info['masked'], a_channel=info['channel'], a_purpose=info['purpose'])
    resp = redirect(url_for('account.code'), 303)
    _set_cookie(resp, PENDING_COOKIE, pending, 1800)
    return resp


@bp.get('/code')
def code():
    if not request.cookies.get(PENDING_COOKIE) or not session.get('a_masked'):
        return redirect(url_for('account.signin'), 303)
    return _page('account/code.html', masked=session['a_masked'], channel=session.get('a_channel'), purpose=session.get('a_purpose'),
                 contact=session.get('a_contact', ''), stamp=_form_stamp(), app_name=_client_for_next(session.get('a_next')), error=None)


@bp.post('/code')
def code_post():
    _check_csrf()
    try:
        user, purpose = accounts.verify(request.cookies.get(PENDING_COOKIE), request.form.get('code'))
    except accounts.AuthError as e:
        return _page('account/code.html', e.status, masked=session.get('a_masked', ''), channel=session.get('a_channel'),
                     purpose=session.get('a_purpose'), contact=session.get('a_contact', ''), stamp=_form_stamp(),
                     app_name=_client_for_next(session.get('a_next')), error=str(e))
    return _signed_in(user, _after_sign_in(new=purpose == 'signup'))


LINK = re.compile(r'^[A-Za-z0-9_-]{20,64}$')


@bp.get('/link')
def link():
    t = request.args.get('t', '')
    row = accounts.link_info(t) if LINK.match(t) else None
    if not row:
        return _page('account/message.html', 410, title='This link has expired',
                     text='Sign-in links work for 10 minutes and only once. Go back and request a new code.')
    if accounts.pending_matches(request.cookies.get(PENDING_COOKIE), row):   # opened in the browser that asked: just finish
        user, purpose = accounts.link_complete(t)
        if purpose.startswith('add_'):
            resp = redirect(url_for('account.home', confirmed=1), 303)
            resp.delete_cookie(PENDING_COOKIE, path='/')
            return resp
        return _signed_in(user, _after_sign_in(new=purpose == 'signup'))
    code_ = accounts.code_for_link(t)
    adding = row['purpose'].startswith('add_')
    return _page('account/link.html', code=code_, token=t, adding=adding,
                 what=('confirm this ' + ('email address' if row['channel'] == 'email' else 'number')) if adding else 'sign in')


@bp.post('/link')
def link_post():
    _check_csrf()
    t = request.form.get('t', '')
    row = accounts.link_info(t) if LINK.match(t) else None
    if not row or row['purpose'] not in ('login', 'signup'):
        return _page('account/message.html', 410, title='This link has expired', text='Go back and request a new code.')
    user, purpose = accounts.link_complete(t)
    return _signed_in(user, _after_sign_in(new=purpose == 'signup'))


@bp.post('/signout')
def signout():
    _check_csrf()
    u = current_user()
    accounts.end_session(request.cookies.get(SESSION_COOKIE), everywhere_for=u['id'] if u and request.form.get('everywhere') else None)
    resp = redirect(url_for('index'), 303)
    resp.delete_cookie(SESSION_COOKIE, path='/')
    return resp


@bp.get('/signout')
def signout_for_app():
    """An app's "Sign out of Happy Hacks too": end this browser's Happy Hacks session, then go back to the app."""
    accounts.end_session(request.cookies.get(SESSION_COOKIE))
    back = sso.safe_return(request.args.get('return_to'))
    resp = redirect(back or url_for('index'), 303)
    resp.delete_cookie(SESSION_COOKIE, path='/')
    return resp


# ------------------------------------------------------------------ your account
def _need_user():
    u = current_user()
    if not u:
        raise _Redirect(url_for('account.signin', next=request.full_path.rstrip('?')))
    return u


class _Redirect(Exception):
    def __init__(self, to):
        self.to = to


@bp.errorhandler(_Redirect)
def _redirect(e):
    return redirect(e.to, 303)


def _home(user, status=200, **kw):
    apps = [p for p in PRODUCTS if p.get('url')]
    return _page('account/home.html', status, user=accounts.public(user), apps=apps, devices=len(accounts.sessions_of(user['id'])),
                 adding=session.get('a_add'), welcome=request.args.get('welcome'), confirmed=request.args.get('confirmed'), **kw)


@bp.get('')
def home():
    return _home(_need_user())


@bp.post('/name')
def name():
    _check_csrf()
    u = _need_user()
    try:
        u = accounts.update_name(u['id'], request.form.get('name'))
    except accounts.AuthError as e:
        return _home(u, e.status, error=str(e))
    return redirect(url_for('account.home', saved=1), 303)


@bp.post('/contact')
def contact_add():
    _check_csrf()
    u = _need_user()
    value = (request.form.get('contact') or '').strip()
    try:
        channel, _ = accounts.parse_contact(value)
        pending, info = accounts.start(value, purpose='add_email' if channel == 'email' else 'add_phone', user_id=u['id'], ip=request.remote_addr)
        accounts.send(info, _base_url())
    except accounts.AuthError as e:
        return _home(u, e.status, error=str(e))
    except Exception as e:   # noqa: BLE001
        return _home(u, 502, error=str(e) if e.__class__.__name__ == 'SendError' else 'The code could not be sent. Try again.')
    session['a_add'] = {'channel': channel, 'masked': info['masked']}
    resp = redirect(url_for('account.home') + '#signin-ways', 303)
    _set_cookie(resp, PENDING_COOKIE, pending, 1800)
    return resp


@bp.post('/contact/verify')
def contact_verify():
    _check_csrf()
    u = _need_user()
    try:
        accounts.verify(request.cookies.get(PENDING_COOKIE), request.form.get('code'), purposes=('add_email', 'add_phone'))
    except accounts.AuthError as e:
        return _home(u, e.status, error=str(e))
    session.pop('a_add', None)
    resp = redirect(url_for('account.home', confirmed=1), 303)
    resp.delete_cookie(PENDING_COOKIE, path='/')
    return resp


@bp.post('/contact/cancel')
def contact_cancel():
    _check_csrf()
    session.pop('a_add', None)
    return redirect(url_for('account.home'), 303)


@bp.post('/contact/remove')
def contact_remove():
    _check_csrf()
    u = _need_user()
    try:
        accounts.remove_contact(u['id'], 'email' if request.form.get('channel') == 'email' else 'sms')
    except accounts.AuthError as e:
        return _home(u, e.status, error=str(e))
    return redirect(url_for('account.home'), 303)


@bp.post('/devices/signout')
def devices_signout():
    """Sign out everywhere else: every session ends, and this browser gets a fresh one."""
    _check_csrf()
    u = _need_user()
    accounts.end_session(None, everywhere_for=u['id'])
    return _signed_in(u, redirect(url_for('account.home', others=1), 303))


# ------------------------------------------------------------------ Sign in with Happy Hacks (for apps)
@bp.get('/authorize')
def authorize():
    try:
        c, p = sso.check_authorize(request.args)
    except sso.SSOError as e:
        return _page('account/message.html', 400, cid=request.args.get('client_id'), title='Can\'t sign in to this app', text=str(e))
    u = current_user()
    if not u:   # screen_hint=signup: the app's "Try it free" button, so open on "Create your free account"
        return redirect(url_for('account.signin', next=request.full_path, new=1 if request.args.get('screen_hint') == 'signup' else None), 303)
    code_ = sso.issue_code(c['id'], u['id'], p['redirect_uri'], p['challenge'])
    sep = '&' if '?' in p['redirect_uri'] else '?'
    return redirect(p['redirect_uri'] + sep + urlencode({'code': code_, 'state': p['state']}), 303)


@bp.post('/token')
def token():
    f = request.form if request.form else (request.get_json(silent=True) or {})
    cid, secret = f.get('client_id'), f.get('client_secret')
    if request.authorization and request.authorization.type == 'basic':
        cid, secret = request.authorization.username, request.authorization.password
    try:
        user = sso.exchange(cid, secret, f.get('code'), f.get('redirect_uri'), f.get('code_verifier'))
    except sso.SSOError as e:
        resp = jsonify(error=e.error, error_description=str(e))
        resp.status_code = e.status
    else:
        resp = jsonify(user=user)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@bp.errorhandler(accounts.AuthError)
def auth_error(e):
    return _page('account/message.html', e.status, title='Something went wrong', text=str(e))
