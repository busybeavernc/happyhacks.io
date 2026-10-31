"""happyhacks.io — parent site for small software products."""
import os
from datetime import timedelta

from flask import Flask, abort, render_template, send_from_directory, url_for

from werkzeug.middleware.proxy_fix import ProxyFix

from .products import PRODUCTS, get_product


def create_app() -> Flask:
    app = Flask(
        __name__,
        # static/ is at the repo root; install.sh copies it to htdocs/<domain>/static,
        # since CloudPanel's vhost serves css/js/images from htdocs, not from the app.
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
        static_url_path="/static",
    )
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Secure cookies need HTTPS; set SESSION_COOKIE_SECURE=0 in .env for plain-http local dev
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") != "0",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    # nginx (CloudPanel) sits in front: trust its X-Forwarded-For/-Proto so client IPs and https are right
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from .admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_globals():
        return {"products": PRODUCTS, "site_name": "Happy Hacks", "asset": asset}

    def asset(filename: str) -> str:
        """Static URL with a ?v=<mtime> suffix. CloudPanel's vhost caches css/js/images
        forever (expires max), so a changed file needs a new URL to reach browsers."""
        try:
            v = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
        except OSError:
            v = 0
        return url_for("static", filename=filename, v=v)

    @app.route("/favicon.ico")
    def favicon():
        # In production nginx serves this from htdocs (install.sh copies it there).
        return send_from_directory(app.static_folder, "favicon.ico")

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/products/<slug>")
    def product(slug: str):
        item = get_product(slug)
        if item is None:
            abort(404)
        return render_template("product.html", product=item)

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    return app
