"""
Flask application factory for the Enterprise Cybersecurity Assessment Platform.

Offline-first: all assets are bundled/local, no CDN, no external fonts/JS.
AWS and other integrations are optional and never block startup.
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime

from flask import Flask, render_template

# make ``src`` importable whether launched as a module or a script
import sys
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from utils.config import load_env  # noqa: E402


def _bootstrap_admin(store) -> None:
    """Ensure at least one admin account exists (offline default)."""
    if store.user_count() == 0:
        pwd = os.environ.get("ADMIN_PASSWORD", "admin")
        store.create_user("admin", pwd, "ADMIN")
        # seed the other roles for demonstration of RBAC
        store.create_user("analyst", os.environ.get("ANALYST_PASSWORD", "analyst"), "SECURITY_ANALYST")
        store.create_user("auditor", os.environ.get("AUDITOR_PASSWORD", "auditor"), "AUDITOR")
        store.create_user("viewer", os.environ.get("VIEWER_PASSWORD", "viewer"), "VIEWER")
        print("=" * 64)
        print(" Default accounts created (change these immediately):")
        print("   admin / %s        [ADMIN]" % pwd)
        print("   analyst / analyst   [SECURITY_ANALYST]")
        print("   auditor / auditor   [AUDITOR]")
        print("   viewer / viewer     [VIEWER]")
        print("=" * 64)


def create_app(config: dict | None = None) -> Flask:
    load_env()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    )
    if config:
        app.config.update(config)

    from core.store import get_store
    store = get_store()
    _bootstrap_admin(store)

    # blueprints
    from .auth import bp as auth_bp
    from .routes_ui import bp as ui_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(ui_bp)

    # ---- context + filters ---------------------------------------------- #
    from . import auth as authmod
    from .icons import icon
    from .registry_ctx import register_context
    register_context(app, icon, authmod)

    @app.errorhandler(403)
    def _403(e):
        return render_template("error.html", code=403,
                               msg="You do not have permission for this action."), 403

    @app.errorhandler(404)
    def _404(e):
        return render_template("error.html", code=404,
                               msg="Page not found."), 404

    return app


# backward-compatible module-level app (so `python -m src.webapp` keeps working)
app = create_app()
