import os
import tempfile
import time
import unittest
from unittest import mock

from happyhacks import admin, create_app


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            'ADMIN_PASSWORD': 'test-pw',
            'UPDATES_DIR': self.tmp.name,
            'UPDATE_COMMAND': 'echo deploying; echo done',
        })
        self.env.start()
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

    def test_disabled_without_password(self):
        with mock.patch.dict(os.environ, {'ADMIN_PASSWORD': ''}):
            self.assertEqual(self.c.get('/admin/login').status_code, 503)

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
