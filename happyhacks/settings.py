"""Settings from the environment (.env is loaded by wsgi.py). Real environment variables win."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, '') else default


def db_settings():
    """MySQL settings, or None when DB_NAME is empty (then a SQLite file in DATA_DIR is used: fine for development)."""
    name = get('DB_NAME')
    if not name:
        return None
    return {'host': get('DB_HOST', '127.0.0.1'), 'port': int(get('DB_PORT', 3306)), 'database': name,
            'user': get('DB_USER', name), 'password': get('DB_PASSWORD', ''), 'unix_socket': get('DB_SOCKET')}


def data_dir():
    return get('DATA_DIR') or os.path.join(ROOT, 'data')


def public_url():
    return (get('PUBLIC_URL') or 'https://happyhacks.io').rstrip('/')
