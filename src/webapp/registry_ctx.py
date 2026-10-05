"""Template context processors and Jinja filters."""
from __future__ import annotations

from datetime import datetime

from markupsafe import Markup


def register_context(app, icon, authmod):
    from core.registry import NAV, stats as module_stats

    @app.context_processor
    def _inject():
        from core.engine import collector_status
        return {
            "NAV": NAV,
            "all_collectors_ctx": collector_status(),
            "icon": lambda name, cls="": Markup(icon(name, cls)),
            "current_user": authmod.current_user(),
            "current_role": authmod.current_role(),
            "can": authmod.can,
            "csrf_token": authmod.csrf_token,
            "module_stats": module_stats(),
            "now": datetime.now,
            "SEVERITIES": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"],
            "STATUSES": ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "REMEDIATED",
                         "FALSE_POSITIVE", "ACCEPTED_RISK"],
        }

    @app.template_filter("sev")
    def _sev(value):
        v = str(value or "INFO").upper()
        return Markup(f'<span class="badge sev-{v}"><span class="dot"></span>{v}</span>')

    @app.template_filter("status")
    def _status(value):
        v = str(value or "OPEN").upper()
        label = v.replace("_", " ").title()
        return Markup(f'<span class="st st-{v}">{label}</span>')

    @app.template_filter("dt")
    def _dt(value):
        if not value:
            return "—"
        try:
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")
            s = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(s).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(value)

    @app.template_filter("ago")
    def _ago(value):
        try:
            s = str(value).replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)
            delta = datetime.utcnow() - dt
            secs = int(delta.total_seconds())
            if secs < 60:
                return "just now"
            if secs < 3600:
                return f"{secs // 60}m ago"
            if secs < 86400:
                return f"{secs // 3600}h ago"
            return f"{secs // 86400}d ago"
        except Exception:
            return "—"
