"""
Authentication, role-based access control (RBAC) and CSRF protection.

Session based, no external dependencies. Roles (spec §20):
    ADMIN            - full control incl. running fixes, user & settings mgmt
    SECURITY_ANALYST - run audits, triage findings, run/preview remediation
    AUDITOR          - run audits, change finding status, export (no fix exec)
    VIEWER           - read only
"""
from __future__ import annotations

import functools
import secrets
from typing import Callable

from flask import (Blueprint, abort, redirect, render_template, request,
                   session, url_for)

bp = Blueprint("auth", __name__)

ROLES = ["ADMIN", "SECURITY_ANALYST", "AUDITOR", "VIEWER"]

# capability matrix
CAPS = {
    "run_audit":       {"ADMIN", "SECURITY_ANALYST", "AUDITOR"},
    "change_status":   {"ADMIN", "SECURITY_ANALYST", "AUDITOR"},
    "preview_fix":     {"ADMIN", "SECURITY_ANALYST"},
    "execute_fix":     {"ADMIN"},
    "manage_users":    {"ADMIN"},
    "manage_settings": {"ADMIN"},
    "export":          {"ADMIN", "SECURITY_ANALYST", "AUDITOR", "VIEWER"},
    "view":            set(ROLES),
}


def current_user():
    return session.get("user")


def current_role() -> str:
    u = session.get("user")
    return u.get("role", "VIEWER") if u else "VIEWER"


def can(cap: str) -> bool:
    return current_role() in CAPS.get(cap, set())


def login_required(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def wrapper(*a, **k):
        if not current_user():
            return redirect(url_for("auth.login", next=request.path))
        return fn(*a, **k)
    return wrapper


def require_cap(cap: str) -> Callable:
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*a, **k):
            if not current_user():
                return redirect(url_for("auth.login", next=request.path))
            if not can(cap):
                abort(403)
            return fn(*a, **k)
        return wrapper
    return deco


# ---- CSRF --------------------------------------------------------------- #
def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["_csrf"] = tok
    return tok


def check_csrf() -> bool:
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    return bool(sent) and secrets.compare_digest(sent, session.get("_csrf", ""))


# ---- routes ------------------------------------------------------------- #
@bp.route("/login", methods=["GET", "POST"])
def login():
    from core.store import get_store
    error = None
    if request.method == "POST":
        if not check_csrf():
            error = "Invalid session token. Please try again."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = get_store().verify_user(username, password)
            if user:
                session.clear()
                session["user"] = user
                get_store().log(username, "login",
                                f"role={user['role']}", request.remote_addr or "")
                nxt = request.args.get("next") or url_for("ui.dashboard")
                if not nxt.startswith("/"):
                    nxt = url_for("ui.dashboard")
                return redirect(nxt)
            error = "Invalid credentials."
            get_store().log(username or "?", "login_failed", "", request.remote_addr or "")
    return render_template("login.html", error=error)


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    user = current_user()
    if user:
        from core.store import get_store
        get_store().log(user.get("username", "?"), "logout", "", request.remote_addr or "")
    session.clear()
    return redirect(url_for("auth.login"))
