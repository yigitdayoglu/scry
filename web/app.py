"""Flask app factory."""

from __future__ import annotations

from flask import Flask

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

from core.database import init_db
from core import scheduler as scheduler_mod
from web.routes import bp


def create_app(start_scheduler: bool = True) -> Flask:
    app = Flask(__name__)
    app.secret_key = config.FLASK_SECRET_KEY

    init_db()
    app.register_blueprint(bp)

    if start_scheduler:
        scheduler_mod.start()

    return app
