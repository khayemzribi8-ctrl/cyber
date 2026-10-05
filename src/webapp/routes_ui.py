"""
Enterprise dashboard routes.

All pages read from the persisted audit data (SQLite) and the core analytics
engines. Real-time audits run in a background thread and report progress via a
polling endpoint. No page fabricates security data: when no audit has run, the
UI shows an honest empty state and offers to run an assessment.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from flask import (Blueprint, Response, abort, jsonify, redirect,
                   render_template, request, session, url_for)

from core.attack_paths import build_paths
from core.compliance import evaluate as evaluate_compliance
from core.engine import (ALL_COLLECTOR_KEYS, COLLECTORS, PIPELINE,
                         collector_status, run_audit)
from core.mitre import get_engine as get_mitre
from core.models import FindingStatus, Severity, summarize
from core.registry import (GROUPS, MODULES, NAV, get_module, modules_by_group,
                           stats as module_stats)
from core.scoring import posture, security_score
from core.store import get_store
from . import svg
from .auth import can, check_csrf, current_user, login_required, require_cap
from .remediation import ALLOWLIST, build_remediation_items, execute_command

bp = Blueprint("ui", __name__)


# --------------------------------------------------------------------------- #
# data loading
# --------------------------------------------------------------------------- #
def _analytics(findings):
    comp = evaluate_compliance(findings)
    score = security_score(findings, compliance_penalty=comp["penalty"])
    return {
        "findings": findings,
        "summary": summarize(findings),
        "score": score,
        "compliance": comp,
        "posture": posture(findings),
        "coverage": get_mitre().coverage(findings),
        "attack_paths": build_paths(findings),
    }


def _load(audit_id: Optional[str] = None) -> Dict[str, Any]:
    store = get_store()
    aid = audit_id or store.latest_audit_id()
    if not aid:
        return {"audit": None, "findings": [], "assets": [], "has_data": False,
                **_analytics([])}
    run = store.get_audit(aid)
    findings = store.get_findings(aid)
    data = {"audit": run, "assets": store.get_assets(aid), "has_data": True}
    data.update(_analytics(findings))
    return data


@bp.before_request
def _guard():
    if not current_user():
        return redirect(url_for("auth.login", next=request.path))


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@bp.route("/")
def dashboard():
    d = _load()
    s = d["summary"]
    # score trend from history
    audits = get_store().list_audits(limit=30)
    trend = [a.security_score for a in reversed(audits)] or [d["score"]["score"]]
    kpis = [
        ("Security Score", d["score"]["score"], d["score"]["grade"], "accent"),
        ("Critical", s.get("CRITICAL", 0), "findings", "crit"),
        ("High", s.get("HIGH", 0), "findings", "high"),
        ("Medium", s.get("MEDIUM", 0), "findings", "med"),
        ("Low", s.get("LOW", 0), "findings", "low"),
        ("Assets", len(d["assets"]), "in scope", ""),
        ("Open Findings", s.get("OPEN", 0), "need action", ""),
        ("Remediated", s.get("REMEDIATED", 0), "resolved", "ok"),
    ]
    donut = svg.donut([(k, s.get(k, 0)) for k in
                       ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")])
    gauge = svg.gauge(d["score"]["score"])
    spark = svg.sparkline([float(x) for x in trend])
    posture_bars = svg.hbars([
        (p["domain"], p["score"] if p["score"] is not None else 0,
         svg._score_color(p["score"]) if p["score"] is not None else "#cbd5e1")
        for p in d["posture"]
    ], max_val=100)
    recent = sorted(d["findings"],
                    key=lambda f: (-f.severity_enum.rank, f.last_seen), reverse=False)
    recent = [f for f in sorted(d["findings"], key=lambda f: -f.severity_enum.rank)
              if f.severity_enum.rank >= 1][:8]
    return render_template("dashboard.html", d=d, kpis=kpis, donut=donut,
                           gauge=gauge, spark=spark, posture_bars=posture_bars,
                           recent=recent, coverage=d["coverage"],
                           attack_paths=d["attack_paths"][:3],
                           collectors=collector_status())


# --------------------------------------------------------------------------- #
# Security assessment (module catalogue + run)
# --------------------------------------------------------------------------- #
@bp.route("/assessment")
def assessment():
    groups = modules_by_group()
    d = _load()
    # findings per module
    per_mod: Dict[str, Dict[str, int]] = {}
    for f in d["findings"]:
        m = per_mod.setdefault(f.module, {"total": 0, "max": "OK"})
        m["total"] += 1
        if Severity.coerce(f.severity).rank > Severity.coerce(m["max"]).rank:
            m["max"] = f.severity_enum.value
    return render_template("assessment.html", groups=groups, GROUPS=GROUPS,
                           per_mod=per_mod, stats=module_stats(),
                           collectors=collector_status(), d=d,
                           all_collectors=ALL_COLLECTOR_KEYS)


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
@bp.route("/assets")
def assets():
    d = _load()
    return render_template("assets.html", d=d, assets=d["assets"])


# --------------------------------------------------------------------------- #
# Module detail (generic, registry-driven)
# --------------------------------------------------------------------------- #
@bp.route("/module/<key>")
def module(key):
    mod = get_module(key)
    if not mod:
        abort(404)
    d = _load()
    # hub modules aggregate all findings in their group (so the main page a nav
    # item points to is never empty while sibling sub-modules hold the data)
    HUBS = {"aws_iam_audit": "Cloud"}
    if key in HUBS:
        findings = [f for f in d["findings"]
                    if (get_module(f.module) and get_module(f.module).group == HUBS[key])]
    else:
        findings = [f for f in d["findings"] if f.module == key]
    findings.sort(key=lambda f: -f.severity_enum.rank)
    # collector status for this module
    col = COLLECTORS.get(mod.collector) if mod.collector else None
    if not mod.collector:
        col_state, col_reason = "planned", ""
    elif col is None:
        # pseudo-collector (e.g. "engine" aggregator) — not a runnable collector
        col_state, col_reason = "aggregated", ""
    elif col.available():
        col_state, col_reason = "ready", ""
    else:
        col_state, col_reason = "needs_library", ", ".join(col.needs)
    techniques = [(t, get_mitre().technique_name(t)) for t in mod.mitre]
    return render_template("module.html", mod=mod, findings=findings, d=d,
                           col_state=col_state, col_reason=col_reason,
                           techniques=techniques, summary=summarize(findings))


# --------------------------------------------------------------------------- #
# Network exposure
# --------------------------------------------------------------------------- #
@bp.route("/network")
def network():
    d = _load()
    from core.collectors.network_exposure import PORT_MAP
    rows = []
    for f in d["findings"]:
        if f.module in ("network_exposure_scanner", "open_port_audit",
                        "rdp_security_audit", "smb_security_audit",
                        "winrm_security_audit", "ssh_security_audit") or \
           f.signature.startswith("NET_"):
            for a in (f.affected or [f.asset]):
                port = ""
                if ":" in str(a):
                    port = str(a).rsplit(":", 1)[-1]
                elif str(a).isdigit():
                    port = str(a)
                rows.append({
                    "host": f.asset or d["audit"].target if d["audit"] else f.asset,
                    "port": port, "service": _svc_for(f, port, PORT_MAP),
                    "severity": f.severity_enum.value, "finding": f,
                })
    return render_template("network.html", d=d, rows=rows)


def _svc_for(f, port, port_map):
    if port and port.isdigit():
        meta = port_map.get(int(port))
        if meta:
            return meta["service"]
    # derive from title
    return f.title.split(" exposed")[0] if "exposed" in f.title else f.title


@bp.route("/attack-surface")
def attack_surface():
    d = _load()
    exposed = [f for f in d["findings"] if f.signature.startswith("NET_")
               and f.severity_enum.rank >= 2]
    return render_template("attack_surface.html", d=d, exposed=exposed,
                           assets=d["assets"])


# --------------------------------------------------------------------------- #
# MITRE ATT&CK
# --------------------------------------------------------------------------- #
@bp.route("/mitre")
def mitre():
    d = _load()
    return render_template("mitre.html", d=d, coverage=d["coverage"])


@bp.route("/mitre/<tid>")
def mitre_technique(tid):
    eng = get_mitre()
    tech = eng.technique(tid)
    if not tech:
        abort(404)
    d = _load()
    related = [f for f in d["findings"]
               if any(m.technique_id == tid for m in f.mitre)]
    assets = sorted({f.asset for f in related if f.asset})
    return render_template("mitre_technique.html", tech=tech, related=related,
                           assets=assets, d=d)


# --------------------------------------------------------------------------- #
# Attack paths
# --------------------------------------------------------------------------- #
@bp.route("/attack-paths")
def attack_paths():
    d = _load()
    return render_template("attack_paths.html", d=d, paths=d["attack_paths"])


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@bp.route("/findings")
def findings():
    d = _load()
    sev = request.args.get("severity", "")
    status = request.args.get("status", "")
    module_f = request.args.get("module", "")
    q = (request.args.get("q", "") or "").lower()
    items = d["findings"]
    if sev:
        items = [f for f in items if f.severity_enum.value == sev]
    if status:
        items = [f for f in items if f.status == status]
    if module_f:
        items = [f for f in items if f.module == module_f]
    if q:
        items = [f for f in items if q in (f.title + f.asset + f.description).lower()]
    items = sorted(items, key=lambda f: (-f.severity_enum.rank, f.module))
    mods = sorted({f.module for f in d["findings"]})
    return render_template("findings.html", d=d, items=items, mods=mods,
                           sev=sev, status=status, module_f=module_f, q=q)


@bp.route("/finding/<fid>")
def finding_detail(fid):
    d = _load()
    f = next((x for x in d["findings"] if x.id == fid), None)
    if not f:
        abort(404)
    # attach a deterministic library remediation when the collector gave none
    if (not f.remediation or not (f.remediation.powershell or f.remediation.linux)) \
            and f.severity_enum.rank >= 2:
        from core.remediation_library import remediation_for
        lib = remediation_for(f)
        if lib:
            f.remediation = lib
    mod = get_module(f.module)
    return render_template("finding_detail.html", d=d, f=f, mod=mod)


@bp.route("/finding/<fid>/status", methods=["POST"])
@require_cap("change_status")
def finding_status(fid):
    if not check_csrf():
        abort(400)
    status = request.form.get("status", "")
    if status not in [s.value for s in FindingStatus]:
        abort(400)
    aid = get_store().latest_audit_id()
    ok = get_store().update_finding_status(aid, fid, status)
    get_store().log(current_user()["username"], "finding_status",
                    f"{fid} -> {status}", request.remote_addr or "")
    if request.headers.get("X-Requested-With"):
        return jsonify({"ok": ok, "status": status})
    return redirect(url_for("ui.finding_detail", fid=fid))


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@bp.route("/evidence")
def evidence():
    d = _load()
    items = []
    for f in d["findings"]:
        for ev in f.evidence:
            items.append({"finding": f, "ev": ev})
    return render_template("evidence.html", d=d, items=items)


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
@bp.route("/remediation")
def remediation():
    d = _load()
    items = build_remediation_items(d["findings"])
    return render_template("remediation.html", d=d, items=items,
                           allowlist=ALLOWLIST)


@bp.route("/remediation/ai-suggest", methods=["POST"])
@require_cap("preview_fix")
def remediation_ai_suggest():
    if not check_csrf():
        return jsonify({"ok": False, "message": "Invalid CSRF token"}), 400
    data = request.get_json(silent=True) or {}
    fid = data.get("finding_id", "")
    d = _load()
    f = next((x for x in d["findings"] if x.id == fid), None)
    if not f:
        return jsonify({"ok": False, "message": "Finding not found"}), 404
    from .recommendation_engine import ai_suggest_command
    mod = get_module(f.module)
    if (mod and mod.group == "Cloud") or f.signature.upper().startswith("AWS_"):
        platform = "aws"
    elif mod and mod.group == "Linux":
        platform = "linux"
    else:
        platform = "windows"
    result = ai_suggest_command(f.title, f.description, f.affected, platform=platform)
    get_store().log(current_user()["username"], "ai_suggest", fid, request.remote_addr or "")
    return jsonify(result)


@bp.route("/remediation/execute", methods=["POST"])
@require_cap("execute_fix")
def remediation_execute():
    if not check_csrf():
        return jsonify({"ok": False, "message": "Invalid CSRF token"}), 400
    data = request.get_json(silent=True) or {}
    fid = data.get("finding_id", "")
    channel = data.get("channel", "winrm")
    d = _load()
    f = next((x for x in d["findings"] if x.id == fid), None)
    if not f:
        return jsonify({"ok": False, "message": "Finding not found"}), 404
    result = execute_command(f, channel)
    get_store().log(current_user()["username"], "remediation_execute",
                    f"{fid} channel={channel} ok={result['ok']}", request.remote_addr or "")
    return jsonify(result)


# --------------------------------------------------------------------------- #
# Compliance
# --------------------------------------------------------------------------- #
@bp.route("/compliance")
def compliance():
    d = _load()
    fw = request.args.get("framework", "")
    controls = d["compliance"]["controls"]
    if fw:
        controls = [c for c in controls if c["framework"] == fw]
    return render_template("compliance.html", d=d, controls=controls,
                           frameworks=d["compliance"]["frameworks"], fw=fw)


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
@bp.route("/reports")
def reports():
    d = _load()
    audits = get_store().list_audits(limit=50)
    return render_template("reports.html", d=d, audits=audits)


@bp.route("/report/<audit_id>.<fmt>")
@require_cap("export")
def report_export(audit_id, fmt):
    from core.reporting import build_csv, build_json, build_html, build_pdf
    d = _load(audit_id)
    if not d["has_data"]:
        abort(404)
    if fmt == "csv":
        return Response(build_csv(d), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=report_{audit_id}.csv"})
    if fmt == "json":
        return Response(build_json(d), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=report_{audit_id}.json"})
    if fmt == "html":
        return Response(build_html(d, render_template),
                        mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=report_{audit_id}.html"})
    if fmt == "pdf":
        pdf = build_pdf(d, render_template)
        if pdf is None:
            return "PDF export requires the optional 'weasyprint' package.", 501
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=report_{audit_id}.pdf"})
    abort(404)


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
@bp.route("/history")
def history():
    audits = get_store().list_audits(limit=100)
    return render_template("history.html", audits=audits, d=_load())


@bp.route("/history/<audit_id>")
def history_detail(audit_id):
    d = _load(audit_id)
    if not d["has_data"]:
        abort(404)
    return render_template("history_detail.html", d=d)


# --------------------------------------------------------------------------- #
# Automation, Settings
# --------------------------------------------------------------------------- #
@bp.route("/automation")
def automation():
    from utils.aws_sns import sns_enabled
    return render_template("automation.html", d=_load(),
                           collectors=collector_status(), sns_on=sns_enabled())


@bp.route("/sns-test", methods=["POST"])
@require_cap("manage_settings")
def sns_test():
    if not check_csrf():
        return jsonify({"ok": False, "message": "Invalid CSRF token"}), 400
    from utils.aws_sns import send_sns_alert, sns_enabled
    if not sns_enabled():
        return jsonify({"ok": False, "message":
                        "SNS non activé — définissez SNS_ENABLED=true et SNS_TOPIC_ARN dans .env, "
                        "puis redémarrez."})
    ok, detail = send_sns_alert("[Sentinel] Test alert",
                                "Ceci est une alerte de test SNS depuis Sentinel. "
                                "Si vous la recevez, la configuration est correcte.")
    get_store().log(current_user()["username"], "sns_test", f"ok={ok} {detail[:120]}")
    if ok:
        return jsonify({"ok": True, "message": f"Alerte envoyée (MessageId {detail}). "
                        "Vérifiez votre email/SMS — l'abonnement au topic doit être CONFIRMÉ."})
    return jsonify({"ok": False, "message": f"Échec SNS : {detail}"})


@bp.route("/settings")
def settings():
    users = get_store().list_users() if can("manage_users") else []
    logs = get_store().get_logs(60)
    return render_template("settings.html", d=_load(), users=users, logs=logs,
                           collectors=collector_status())


# --------------------------------------------------------------------------- #
# Run audit (background) + progress
# --------------------------------------------------------------------------- #
_RUNS: Dict[str, Dict[str, Any]] = {}


def _bg_run(token: str, modules: List[str], target: str, actor: str):
    state = _RUNS[token]
    stage_state = {s: "pending" for s in PIPELINE}

    def progress(stage, st):
        stage_state[stage] = st
        done = sum(1 for v in stage_state.values() if v in ("done", "skipped", "error"))
        state["stages"] = dict(stage_state)
        state["percent"] = int(100 * done / len(PIPELINE))

    try:
        res = run_audit(modules=modules, target=target, triggered_by=actor,
                        persist=True, progress=progress)
        state["audit_id"] = res["audit"].audit_id
        state["score"] = res["score"]["score"]
        state["findings"] = len(res["findings"])
        state["percent"] = 100
        state["status"] = "completed"
    except Exception as e:
        state["status"] = "failed"
        state["error"] = str(e)


@bp.route("/run-audit", methods=["POST"])
@require_cap("run_audit")
def run_audit_route():
    if not check_csrf():
        abort(400)
    modules = request.form.getlist("modules") or ALL_COLLECTOR_KEYS
    target = (request.form.get("target") or "").strip()
    token = uuid.uuid4().hex[:10]
    _RUNS[token] = {"status": "running", "percent": 0, "stages": {},
                    "started": time.time()}
    session["run_token"] = token
    actor = current_user()["username"]
    threading.Thread(target=_bg_run, args=(token, modules, target, actor),
                     daemon=True).start()
    return redirect(url_for("ui.audit_running", token=token))


@bp.route("/audit/running/<token>")
def audit_running(token):
    if token not in _RUNS:
        return redirect(url_for("ui.dashboard"))
    return render_template("audit_running.html", token=token, pipeline=PIPELINE,
                           d=_load())


@bp.route("/audit/status/<token>")
def audit_status(token):
    state = _RUNS.get(token)
    if not state:
        return jsonify({"status": "unknown"}), 404
    return jsonify(state)
