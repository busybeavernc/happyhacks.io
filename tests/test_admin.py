import os
import tempfile
import time
import unittest
from unittest import mock

from happyhacks import accounts, admin, create_app


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            'ADMIN_PASSWORD': 'test-pw', 'DATA_DIR': self.tmp.name, 'SECRET_KEY': 'test-secret', 'DB_NAME': '', 'AUTH_DELIVERY': 'log',
            'UPDATES_DIR': self.tmp.name,
            'UPDATE_COMMAND': 'echo deploying; echo done',
        })
        self.env.start()
        accounts.reset()
        admin._failures.clear()
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
        self.assertEqual(self.c.get('/admin').status_code, 302)
        self.assertEqual(self.c.get('/admin/api/updates').status_code, 401)
        self.assertEqual(self.c.post('/admin/api/updates').status_code, 401)

    def test_wrong_password_and_lockout(self):
        for _ in range(5):
            self.assertIn(b'not right', self.c.post('/admin/login', data={'password': 'nope'}).data)
        r = self.c.post('/admin/login', data={'password': 'test-pw'})
        self.assertEqual(r.status_code, 429)

    def test_password_off_leaves_account_sign_in(self):
        with mock.patch.dict(os.environ, {'ADMIN_PASSWORD': ''}):
            page = self.c.get('/admin/login').get_data(as_text=True)
            self.assertIn('Sign in with Happy Hacks', page)
            self.assertNotIn('Admin password', page)
            r = self.c.post('/admin/login', data={'password': ''})
            self.assertIn(b'turned off', r.data)
            self.assertEqual(self.c.get('/admin').status_code, 302)

    def account(self, email, role=None):
        u = accounts.create_user('Pat Admin', 'email', email)
        if role:
            accounts.set_role(u['id'], role)
        self.c.set_cookie('hh_session', accounts.new_session(u['id']))
        return u

    def test_account_admin_goes_straight_in(self):
        self.account('pat@example.com', 'admin')
        self.assertEqual(self.c.get('/admin/login').status_code, 302)
        page = self.c.get('/admin').get_data(as_text=True)
        self.assertIn('Pat Admin', page)
        with self.c.session_transaction() as s:
            csrf = s['csrf']
        r = self.c.post('/admin/api/updates', headers={'X-CSRF-Token': csrf})
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn('Admin', self.c.get('/account').get_data(as_text=True))

    def test_ordinary_account_is_turned_away(self):
        self.account('sam@example.com')
        self.assertEqual(self.c.get('/admin').status_code, 302)
        self.assertEqual(self.c.get('/admin/api/updates').status_code, 401)
        self.assertIn("isn't a Happy Hacks administrator", self.c.get('/admin/login').get_data(as_text=True))

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
