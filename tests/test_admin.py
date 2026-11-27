import os
import tempfile
import time
import unittest
from unittest import mock

from happyhacks import accounts, adminlock, create_app


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            'ADMIN_PASSWORD': 'test-pw', 'ADMIN_RECOVERY': '1', 'ADMIN_ALERT_EMAIL': 'alerts@example.com', 'DATA_DIR': self.tmp.name, 'SECRET_KEY': 'test-secret', 'DB_NAME': '', 'AUTH_DELIVERY': 'log',
            'UPDATES_DIR': self.tmp.name,
            'UPDATE_COMMAND': 'echo deploying; echo done',
        })
        self.env.start()
        accounts.reset()
        adminlock.sent.clear()
        app = create_app()
        app.config['SESSION_COOKIE_SECURE'] = False
        self.c = app.test_client()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def sign_in(self):
        r = self.c.post('/admin/login', data={'password': 'test-pw'})
        self.assertEqual(r.status_code, 302)
        with self.c.session_transaction() as s:
            return s['csrf']

    def test_requires_sign_in(self):
        self.assertEqual(self.c.get('/admin').status_code, 404)
        self.assertEqual(self.c.get('/admin/api/updates').status_code, 404)
        self.assertEqual(self.c.post('/admin/api/updates').status_code, 404)

    def test_wrong_password_and_lockout(self):
        for _ in range(5):
            self.assertIn(b'not right', self.c.post('/admin/login', data={'password': 'nope'}).data)
        r = self.c.post('/admin/login', data={'password': 'test-pw'})
        self.assertEqual(r.status_code, 429)

    def test_password_is_off_without_recovery(self):
        with mock.patch.dict(os.environ, {'ADMIN_RECOVERY': '0'}):
            self.assertEqual(self.c.get('/admin/login').status_code, 404)
            self.assertEqual(self.c.post('/admin/login', data={'password': 'test-pw'}).status_code, 404)
        self.sign_in()
        self.assertEqual(self.c.get('/admin').status_code, 200)
        self.assertTrue(any('recovery password was used' in m['subject'] for m in adminlock.sent))
        with mock.patch.dict(os.environ, {'ADMIN_RECOVERY': '0'}):
            self.assertEqual(self.c.get('/admin').status_code, 404)    # switched off: the session stops working

    def test_totp_matches_rfc_6238(self):
        secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        self.assertEqual(adminlock.code_at(secret, 59 // 30), '287082')
        self.assertEqual(adminlock.code_at(secret, 1111111109 // 30), '081804')
        self.assertEqual(adminlock.check_code(secret, '287 082', 0, now=59), 1)
        self.assertIsNone(adminlock.check_code(secret, '287082', 1, now=59))

    def account(self, email, role=None):
        u = accounts.create_user('Pat Admin', 'email', email)
        if role:
            accounts.set_role(u['id'], role)
        self.c.set_cookie('hh_session', accounts.new_session(u['id']))
        return u

    def totp(self, u):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(accounts._main(['totp', u['email']]), 0)
        return accounts.db().run('SELECT totp_secret FROM users WHERE id=%s', (u['id'],), fetch='one')['totp_secret']

    def unlock(self, secret, step=None):
        self.c.get('/account')
        with self.c.session_transaction() as s:
            csrf = s['csrf']
        code = adminlock.code_at(secret, step if step is not None else int(time.time() // 30))
        return self.c.post('/account/admin-unlock', data={'csrf': csrf, 'code': code})

    def test_account_admin_unlocks_with_authenticator(self):
        u = self.account('pat@example.com', 'admin')
        self.assertEqual(self.c.get('/admin').status_code, 302)                # locked: back to /account
        page = self.c.get('/account').get_data(as_text=True)
        self.assertIn('id="admin-unlock"', page)
        self.assertIn('python -m happyhacks.accounts totp pat@example.com', page)   # no authenticator yet
        self.assertNotIn('>Admin</a>', page)
        secret = self.totp(u)
        self.assertIn('Authenticator code', self.c.get('/account').get_data(as_text=True))
        r = self.unlock(secret)
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers['Location'].endswith('/admin'))
        self.assertTrue(any('Admin was unlocked' in m['subject'] for m in adminlock.sent))
        page = self.c.get('/admin').get_data(as_text=True)
        self.assertIn('Pat Admin', page)
        with self.c.session_transaction() as s:
            csrf = s['csrf']
        r = self.c.post('/admin/api/updates', headers={'X-CSRF-Token': csrf})
        self.assertEqual(r.status_code, 200, r.data)
        self.assertTrue(any('started a website update' in m['subject'] for m in adminlock.sent))
        self.assertIn('>Admin</a>', self.c.get('/account').get_data(as_text=True))
        # 30 minutes without use: locked again, and the old code can't be reused
        with self.c.session_transaction() as s:
            s['admin_unlock'] = {**s['admin_unlock'], 'until': time.time() - 1}
        self.assertIn('admin=locked', self.c.get('/admin').headers['Location'])
        self.assertEqual(self.c.get('/admin/api/updates').status_code, 401)
        self.assertIn('didn&#39;t work', self.unlock(secret).get_data(as_text=True))

    def test_wrong_codes_block_unlocking(self):
        u = self.account('pat@example.com', 'admin')
        secret = self.totp(u)
        self.c.get('/account')
        with self.c.session_transaction() as s:
            csrf = s['csrf']
        for _ in range(5):
            self.c.post('/account/admin-unlock', data={'csrf': csrf, 'code': '000000'})
        self.assertTrue(any('blocked after wrong codes' in m['subject'] for m in adminlock.sent))
        self.assertIn('Too many wrong codes', self.unlock(secret).get_data(as_text=True))

    def test_ordinary_account_sees_nothing(self):
        self.account('sam@example.com')
        self.assertEqual(self.c.get('/admin').status_code, 404)
        self.assertEqual(self.c.get('/admin/api/updates').status_code, 404)
        self.assertNotIn('admin-unlock', self.c.get('/account').get_data(as_text=True))
        with self.c.session_transaction() as s:
            csrf = s['csrf']
        self.assertEqual(self.c.post('/account/admin-unlock', data={'csrf': csrf, 'code': '123456'}).status_code, 404)

    def test_admin_contacts_and_command(self):
        with mock.patch.dict(os.environ, {'ADMIN_CONTACTS': 'Boss+x@Example.com'}):
            u = accounts.create_user('Boss', 'email', 'boss@example.com')
            pending, info = accounts.start('boss@example.com', ip='1.2.3.4')
            user, _ = accounts.verify(pending, info['code'])
            self.assertEqual(user['role'], 'admin')   # listed in ADMIN_CONTACTS: made admin at sign-in
        other = accounts.create_user('Kim', 'email', 'kim@example.com')
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(accounts._main(['admin', 'kim@example.com']), 0)
        self.assertEqual(accounts.get_user(other['id'])['role'], 'admin')
        self.assertNotIn('role', accounts.public(accounts.get_user(other['id'])))   # never sent to apps
        with contextlib.redirect_stdout(io.StringIO()):
            accounts._main(['unadmin', other['id']])
        self.assertEqual(accounts.get_user(other['id'])['role'], 'user')

    def test_post_needs_csrf_token(self):
        self.sign_in()
        self.assertEqual(self.c.post('/admin/api/updates').status_code, 400)

    def test_run_update_and_read_log(self):
        csrf = self.sign_in()
        self.assertEqual(self.c.get('/admin').status_code, 200)
        self.assertEqual(self.c.get('/admin/api/updates?fetch=0').status_code, 200)
        r = self.c.post('/admin/api/updates', headers={'X-CSRF-Token': csrf})
        self.assertEqual(r.status_code, 200, r.data)
        for _ in range(50):
            st = self.c.get('/admin/api/updates/log?from=0').json
            if not st['running'] and st['exit'] is not None:
                break
            time.sleep(0.1)
        self.assertEqual(st['exit'], 0)
        self.assertIn('deploying', st['log'])
        self.assertNotIn('__HAPPYHACKS_EXIT__', st['log'])


if __name__ == '__main__':
    unittest.main()
