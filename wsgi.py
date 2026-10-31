"""WSGI entry point for gunicorn:  gunicorn -c deploy/gunicorn.conf.py wsgi:app"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

from happyhacks import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
