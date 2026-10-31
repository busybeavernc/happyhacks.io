"""Small SQL helper (same as zipzip's autofill/sqldb.py): MySQL when DB_NAME is set, else a SQLite file in DATA_DIR.
Placeholders are %s in both. Tables are created on first use."""
import contextlib
import os
import sqlite3
import threading

from . import settings


class StoreUnavailable(Exception):
    pass


class SQL:
    def __init__(self, mysql_ddl, sqlite_ddl, sqlite_name, migrations=()):
        self.mysql_ddl, self.sqlite_ddl, self.migrations = mysql_ddl, sqlite_ddl, list(migrations)
        self.db = settings.db_settings()
        self.ready = False
        self.lock = threading.Lock()
        if not self.db:
            self.path = os.path.join(settings.data_dir(), sqlite_name)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

    @property
    def mysql(self):
        return bool(self.db)

    def _conn(self):
        if not self.db:
            c = sqlite3.connect(self.path, timeout=10)
            c.row_factory = sqlite3.Row
            return c
        try:
            import pymysql
        except ImportError:
            raise StoreUnavailable('DB_NAME is set but PyMySQL is not installed (pip install -r requirements.txt).')
        s = self.db
        kw = {'user': s['user'], 'password': s['password'], 'database': s['database'], 'charset': 'utf8mb4', 'autocommit': True,
              'connect_timeout': 10, 'read_timeout': 30, 'write_timeout': 30, 'cursorclass': pymysql.cursors.DictCursor}
        if s['unix_socket']:
            kw['unix_socket'] = s['unix_socket']
        else:
            kw.update(host=s['host'], port=s['port'])
        try:
            return pymysql.connect(**kw)
        except pymysql.err.OperationalError as e:
            code = e.args[0] if e.args else None
            hint = {1045: 'the user name or password was refused (check DB_USER / DB_PASSWORD in .env)',
                    1044: f"the user may not use database {s['database']} (grant it access in CloudPanel)",
                    1049: f"database {s['database']} does not exist",
                    2003: f'nothing is listening at {s["host"]}:{s["port"]}'}.get(code, str(e))
            raise StoreUnavailable(f'Could not connect to the accounts database: {hint}.')

    def _prepare(self, c):
        if self.ready:
            return
        with self.lock:
            if not self.ready:
                cur = c.cursor()
                for sql in (self.mysql_ddl if self.db else self.sqlite_ddl):
                    cur.execute(sql)
                c.commit()
                for sql in self.migrations:
                    try:
                        cur.execute(sql)
                        c.commit()
                    except Exception:   # noqa: BLE001 - already applied
                        c.rollback()
                self.ready = True

    def _sql(self, sql):
        return sql if self.db else sql.replace('%s', '?')

    def run(self, sql, args=(), fetch=None):
        """fetch: None -> rowcount, 'all' -> [dict], 'one' -> dict | None"""
        with contextlib.closing(self._conn()) as c:
            self._prepare(c)
            cur = c.cursor()
            cur.execute(self._sql(sql), tuple(args))
            if fetch:
                rows = [dict(r) for r in cur.fetchall()]
                c.commit()
                return rows if fetch == 'all' else (rows[0] if rows else None)
            c.commit()
            return cur.rowcount
