"""Happy Hacks accounts: sign-up, sign-in by code or link, adding a mobile, limits, decoys, and Sign in with Happy Hacks."""
import base64
import hashlib
import os
import re
import secrets
import shutil
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from happyhacks import accounts, create_app, sso

APP_SECRET = 'zz-client-secret'
CALLBACK = 'https://zipzip.example.com/auth/happyhacks/callback'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='hh-')
        self.env = mock.patch.dict(os.environ, {
            'DATA_DIR': self.tmp, 'SECRET_KEY': 'test-secret', 'AUTH_DELIVERY': 'log', 'DB_NAME': '',
            'HH_CLIENTS': 'zipzip', 'HH_CLIENT_ZIPZIP_NAME': 'ZipZip',
            'HH_CLIENT_ZIPZIP_SECRET_SHA256': hashlib.sha256(APP_SECRET.encode()).hexdigest(),
            'HH_CLIENT_ZIPZIP_REDIRECT_URIS': CALLBACK, 'PUBLIC_URL': 'https://happyhacks.io'})
        self.env.start()
        accounts.reset(); sso.reset()
        self.sent = []
        self.p = mock.patch.object(accounts, 'send', lambda info, base, app_name=None: None if info.get('decoy') else self.sent.append((info, app_name)))
        self.p.start()
        app = create_app()
        app.config['SESSION_COOKIE_SECURE'] = False
        self.app = app
        self.c = app.test_client()

    def tearDown(self):
        self.p.stop(); self.env.stop()
        accounts.reset(); sso.reset()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def csrf(self, c=None):
        c = c or self.c
        with c.session_transaction() as s:
            s.setdefault('csrf', 'tok')
            return s['csrf']

    def stamp(self, ago=5):
        """A form stamp as if the form was shown `ago` seconds ago."""
        from itsdangerous import TimestampSigner, URLSafeTimedSerializer

        class Earlier(TimestampSigner):
            def get_timestamp(self):
                return int(time.time()) - ago
        return URLSafeTimedSerializer(self.app.secret_key, salt='hh-form', signer=Earlier).dumps('f')

    def start(self, contact, name='', c=None, **extra):
        c = c or self.c
        return c.post('/account/signin', data={'csrf': self.csrf(c), 'ts': self.stamp(), 'contact': contact, 'name': name, **extra})

    def sign_up(self, contact='jane@example.com', name='Jane Doe', c=None):
        c = c or self.c
        r = self.start(contact, c=c)
        self.assertIn(b'Your name', r.data)          # unknown address: asks for a name
        r = self.start(contact, name, c=c)
        self.assertEqual(r.status_code, 303, r.data[:400])
        code = self.sent[-1][0]['code']
        r = c.post('/account/code', data={'csrf': self.csrf(c), 'code': code})
        self.assertEqual(r.status_code, 303)
        return r


class AccountFlow(Base):
    def test_signup_then_account_page_and_signin_again(self):
        r = self.sign_up()
        self.assertIn('/account?welcome=1', r.headers['Location'])
        page = self.c.get('/account').get_data(as_text=True)
        self.assertIn('Hi, Jane!', page)
        self.assertIn('jane@example.com', page)
        self.assertIn('Jane', self.c.get('/').get_data(as_text=True))   # nav shows the account
        # sign out, then back in with the same inbox written another way
        self.c.post('/account/signout', data={'csrf': self.csrf()})
        self.assertEqual(self.c.get('/account').status_code, 303)
        r = self.start('Jane+news@Example.com')
        self.assertEqual(r.status_code, 303)
        info = self.sent[-1][0]
        self.assertEqual(info['purpose'], 'login')
        self.assertEqual(info['name'], 'Jane Doe')

    def test_wrong_code_and_other_browser(self):
        self.start('sam@example.com', 'Sam')
        r = self.c.post('/account/code', data={'csrf': self.csrf(), 'code': '000000'})
        self.assertIn(b'isn', r.data)
        other = self.app.test_client()   # a code only works in the browser that asked for it
        r = other.post('/account/code', data={'csrf': self.csrf(other), 'code': self.sent[-1][0]['code']})
        self.assertNotEqual(r.status_code, 303)

    def test_link_signs_in_same_browser_and_shows_code_elsewhere(self):
        self.start('lee@example.com', 'Lee')
        t = self.sent[-1][0]['link_token']
        other = self.app.test_client()
        page = other.get(f'/account/link?t={t}').get_data(as_text=True)
        code = self.sent[-1][0]['code']
        self.assertIn(code[:3], page)
        r = self.c.get(f'/account/link?t={t}')
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.c.get('/account').status_code, 200)
        self.assertEqual(other.get(f'/account/link?t={t}').status_code, 410)   # once only

    def test_bot_gets_decoy(self):
        r = self.c.post('/account/signin', data={'csrf': self.csrf(), 'ts': self.stamp(), 'contact': 'x@example.com',
                                                 'name': 'X', 'website': 'http://spam'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.sent, [])
        r = self.c.post('/account/signin', data={'csrf': self.csrf(), 'ts': self.stamp(ago=0), 'contact': 'y@example.com', 'name': 'Y'})
        self.assertEqual(self.sent, [])   # sent in under 1.5 s: a decoy too

    def test_unconfirmed_mobile_gets_decoy_then_add_phone(self):
        r = self.start('919-555-0100')
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.sent, [])   # no account has confirmed this number: nothing is texted
        self.sign_up('pat@example.com', 'Pat')
        r = self.c.post('/account/contact', data={'csrf': self.csrf(), 'contact': '(919) 555-0100'})
        self.assertEqual(r.status_code, 303)
        r = self.c.post('/account/contact/verify', data={'csrf': self.csrf(), 'code': self.sent[-1][0]['code']})
        self.assertEqual(r.status_code, 303)
        self.assertIn('(919) 555-0100', self.c.get('/account').get_data(as_text=True))

    def test_resend_wait(self):
        self.start('rae@example.com', 'Rae')
        r = self.start('rae@example.com', 'Rae')
        self.assertEqual(r.status_code, 429)

    def test_csrf_required(self):
        r = self.c.post('/account/signin', data={'contact': 'a@example.com'})
        self.assertEqual(r.status_code, 400)


class SignInWithHappyHacks(Base):
    def pkce(self):
        v = secrets.token_urlsafe(48)
        return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()

    def authorize(self, challenge, state='s1', **over):
        q = {'client_id': 'zipzip', 'redirect_uri': CALLBACK, 'response_type': 'code', 'state': state,
             'code_challenge': challenge, 'code_challenge_method': 'S256', **over}
        return self.c.get('/account/authorize', query_string=q)

    def token(self, **f):
        return self.c.post('/account/token', data=f)

    def test_full_flow(self):
        verifier, challenge = self.pkce()
        r = self.authorize(challenge)
        self.assertEqual(r.status_code, 303)
        self.assertIn('/account/signin?next=', r.headers['Location'])
        self.c.get(r.headers['Location'])
        self.assertIn(b'continue to <b>ZipZip</b>', self.c.get('/account/signin?keep=1').data)
        r = self.sign_up('ann@example.com', 'Ann')
        self.assertIn('/account/authorize?', r.headers['Location'])   # back to the app's request
        self.assertEqual(self.sent[-1][1], 'ZipZip')                  # the email says where they're going
        r = self.c.get(r.headers['Location'])
        loc = urlsplit(r.headers['Location'])
        self.assertEqual(f'{loc.scheme}://{loc.netloc}{loc.path}', CALLBACK)
        q = parse_qs(loc.query)
        self.assertEqual(q['state'], ['s1'])
        code = q['code'][0]
        r = self.token(client_id='zipzip', client_secret=APP_SECRET, code=code, redirect_uri=CALLBACK, code_verifier=verifier)
        self.assertEqual(r.status_code, 200, r.json)
        self.assertEqual(r.json['user']['email'], 'ann@example.com')
        self.assertTrue(r.json['user']['email_verified'])
        # identity only: no roles or permissions ever go to an app (each app decides those itself)
        self.assertEqual(set(r.json['user']), {'id', 'name', 'email', 'phone', 'email_verified', 'phone_verified', 'phone_display'})
        # one use only
        r = self.token(client_id='zipzip', client_secret=APP_SECRET, code=code, redirect_uri=CALLBACK, code_verifier=verifier)
        self.assertEqual(r.json['error'], 'invalid_grant')
        # already signed in: instant
        verifier2, challenge2 = self.pkce()
        r = self.authorize(challenge2, state='s2')
        self.assertTrue(r.headers['Location'].startswith(CALLBACK + '?code='))

    def test_rejects_bad_requests(self):
        _, challenge = self.pkce()
        self.assertEqual(self.authorize(challenge, client_id='nope').status_code, 400)
        self.assertEqual(self.authorize(challenge, redirect_uri='https://evil.example/cb').status_code, 400)
        self.assertEqual(self.authorize('', code_challenge_method='plain').status_code, 400)

    def test_token_checks_secret_verifier_and_redirect(self):
        self.sign_up('bo@example.com', 'Bo')
        verifier, challenge = self.pkce()
        code = parse_qs(urlsplit(self.authorize(challenge).headers['Location']).query)['code'][0]
        r = self.token(client_id='zipzip', client_secret='wrong', code=code, redirect_uri=CALLBACK, code_verifier=verifier)
        self.assertEqual(r.status_code, 401)
        r = self.token(client_id='zipzip', client_secret=APP_SECRET, code=code, redirect_uri=CALLBACK, code_verifier=self.pkce()[0])
        self.assertEqual(r.json['error'], 'invalid_grant')
        code = parse_qs(urlsplit(self.authorize(challenge).headers['Location']).query)['code'][0]
        r = self.token(client_id='zipzip', client_secret=APP_SECRET, code=code, redirect_uri=CALLBACK + 'x', code_verifier=verifier)
        self.assertEqual(r.json['error'], 'invalid_grant')

    def test_signout_returns_only_to_registered_apps(self):
        self.sign_up('cy@example.com', 'Cy')
        r = self.c.get('/account/signout?return_to=https://zipzip.example.com/')
        self.assertEqual(r.headers['Location'], 'https://zipzip.example.com/')
        r = self.c.get('/account/signout?return_to=https://evil.example/')
        self.assertFalse(r.headers['Location'].startswith('https://evil'))

    def test_import_from_zipzip_keeps_ids(self):
        self.sign_up('taken@example.com', 'Taken')
        res = accounts.import_users([
            {'id': 'u1a2b3c4d5e6f', 'name': 'Zed', 'email': 'zed@example.com', 'email_verified': True, 'phone': '+19195550111', 'phone_verified': True},
            {'id': 'u000000000001', 'name': 'Dup', 'email': 'Taken+x@example.com', 'email_verified': True},
            {'id': 'u000000000002', 'name': 'Nobody'},
        ])
        self.assertEqual(res['added'], 1)
        self.assertEqual(len(res['skipped']), 2)
        u = accounts.get_user('u1a2b3c4d5e6f')
        self.assertTrue(u['phone_verified'])
        self.assertNotIn('role', u)   # a zipzip role doesn't come along (Happy Hacks accounts have none)
        self.assertEqual(accounts.import_users([{'id': 'u1a2b3c4d5e6f', 'email': 'zed@example.com'}])['same'], 1)
        # an imported, confirmed mobile can sign in by text right away
        r = self.start('919-555-0111')
        self.assertEqual(self.sent[-1][0]['purpose'], 'login')


if __name__ == '__main__':
    unittest.main()
