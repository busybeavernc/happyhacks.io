"""gunicorn settings. supervisor runs, from the app folder:  .venv/bin/gunicorn -c deploy/gunicorn.conf.py wsgi:app"""
import multiprocessing
import os

try:
    from dotenv import dotenv_values
    _env = dotenv_values(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))
except ImportError:
    _env = {}


def _setting(name, default):
    return os.environ.get(name) or _env.get(name) or default


# CloudPanel's vhost proxies to this port; it is only reachable from the server itself
bind = _setting('GUNICORN_BIND', f"127.0.0.1:{_setting('APP_PORT', '9010')}")

workers = int(_setting('GUNICORN_WORKERS', min(4, max(2, multiprocessing.cpu_count()))))
timeout = 30
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 100

accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(M)sms'
forwarded_allow_ips = '127.0.0.1'
proc_name = 'happyhacks'
