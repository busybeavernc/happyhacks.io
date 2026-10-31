"""happyhacks.io — parent site for small software products."""
import os

from flask import Flask, abort, render_template

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

    @app.context_processor
    def inject_globals():
        return {"products": PRODUCTS, "site_name": "HappyHacks"}

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
