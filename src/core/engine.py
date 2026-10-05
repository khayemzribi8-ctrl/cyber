"""
Central audit engine / orchestrator.

Shared by both the web dashboard and the CLI. It runs the selected collectors,
normalizes and enriches their output, computes assets, scores and compliance,
persists the run, and returns a full result object.

Collector availability is detected at runtime. Optional integrations (AWS, and
the LDAP/SSH auditors that need extra libraries) degrade gracefully: if a
collector cannot run, the engine records an honest INFO finding
("integration not configured") instead of failing or fabricating results.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import uuid
from typing import Any, Callable, Dict, List, Optional

from .attack_paths import build_paths
from .compliance import evaluate as evaluate_compliance
from .mitre import get_engine as get_mitre
from .models import (Asset, AssetType, AuditRun, Finding, Severity, summarize,
                     utcnow_iso)
from .normalize import normalize
from .registry import MODULES, get_module
from .scoring import posture, security_score
from .store import get_store

# progress pipeline stages shown in the "audit running" UI (spec §12)
PIPELINE = [
    "Asset Discovery", "Windows Checks", "AD Checks", "LDAP Checks",
    "Kerberos Checks", "SMB Checks", "RDP Checks", "WinRM Checks",
    "ADCS Checks", "Network Checks", "AWS Checks", "Findings Engine",
    "MITRE Mapping", "Risk Calculation", "Report",
]


# --------------------------------------------------------------------------- #
# Collector registry: maps a collector key -> a callable + config builder.
# The legacy auditors are wrapped so the engine has one uniform interface.
# --------------------------------------------------------------------------- #
def _env(k: str, default: str = "") -> str:
    return os.environ.get(k, default)


def _cfg_ldap() -> Dict[str, Any]:
    return dict(host=_env("LDAP_HOST", "127.0.0.1"), port=int(_env("LDAP_PORT", "389") or 389),
                use_ssl=_env("LDAP_SSL", "false").lower() in ("1", "true", "yes"),
                bind_dn=_env("LDAP_BIND_DN"), password=_env("LDAP_PASSWORD"),
                base_dn=_env("LDAP_BASE_DN") or None)


def _cfg_ad() -> Dict[str, Any]:
    return dict(host=_env("AD_HOST") or _env("LDAP_HOST", "127.0.0.1"),
                port=int(_env("AD_PORT", "389") or 389), domain=_env("AD_DOMAIN"),
                bind_dn=_env("AD_BIND_DN") or _env("LDAP_BIND_DN"),
                password=_env("AD_PASSWORD") or _env("LDAP_PASSWORD"))


def _cfg_ssh() -> Dict[str, Any]:
    return dict(host=_env("SSH_HOST") or _env("LDAP_HOST", "127.0.0.1"),
                port=int(_env("SSH_PORT", "22") or 22), username=_env("SSH_USERNAME"),
                password=_env("SSH_PASSWORD"), key_path=_env("SSH_KEY_PATH"))


def _cfg_winrm() -> Dict[str, Any]:
    return dict(host=_env("WINRM_HOST") or _env("AD_HOST") or _env("LDAP_HOST", ""),
                port=int(_env("WINRM_PORT", "5985") or 5985),
                username=_env("WINRM_USERNAME"), password=_env("WINRM_PASSWORD"),
                transport=_env("WINRM_TRANSPORT", "ntlm"))


class Collector:
    def __init__(self, key: str, label: str, loader: Callable[[], Callable],
                 config: Callable[[], Dict[str, Any]], optional: bool = False,
                 needs: Optional[List[str]] = None):
        self.key = key
        self.label = label
        self._loader = loader
        self._config = config
        self.optional = optional
        self.needs = needs or []

    def available(self) -> bool:
        for mod in self.needs:
            try:
                if importlib.util.find_spec(mod) is None:
                    return False
            except Exception:
                # a missing/broken parent package raises here — treat as absent
                return False
        return True

    def run(self, target: str = "") -> List[Dict[str, Any]]:
        fn = self._loader()
        cfg = self._config()
        if target and "host" in cfg:
            cfg["host"] = target
        return fn(**cfg)


def _load_auditor(name: str) -> Callable:
    def loader():
        import sys
        src = os.path.dirname(os.path.dirname(__file__))
        if src not in sys.path:
            sys.path.insert(0, src)
        mod = importlib.import_module(f"auditors.{name}")
        return mod.run
    return loader


def _load_network() -> Callable:
    from .collectors import network_exposure
    return network_exposure.run


def _load_core_collector(name: str) -> Callable:
    def loader():
        mod = importlib.import_module(f".collectors.{name}", package="core")
        return mod.run
    return loader


def _build_collectors() -> Dict[str, Collector]:
    return {
        "network": Collector("network", "Network Checks", _load_network,
                             lambda: {"host": _env("LDAP_HOST", "127.0.0.1")}),
        "ad": Collector("ad", "AD Checks", _load_auditor("audit_ad"), _cfg_ad,
                        optional=True, needs=["ldap3"]),
        "ldap": Collector("ldap", "LDAP Checks", _load_auditor("audit_ldap"), _cfg_ldap,
                          optional=True, needs=["ldap3"]),
        "kerberos": Collector("kerberos", "Kerberos Checks", _load_auditor("audit_token"),
                              _cfg_ad, optional=True, needs=["ldap3"]),
        "adcs": Collector("adcs", "ADCS Checks", _load_core_collector("adcs_ldap"),
                          _cfg_ad, optional=True, needs=["ldap3"]),
        "policy": Collector("policy", "AD Policy Checks", _load_core_collector("ad_policy"),
                            _cfg_ad, optional=True, needs=["ldap3"]),
        "windows_winrm": Collector("windows_winrm", "Windows Checks",
                                   _load_core_collector("windows_winrm"), _cfg_winrm,
                                   optional=True, needs=["winrm"]),
        "privilege": Collector("privilege", "AD Checks", _load_auditor("audit_privilege"),
                               _cfg_ad, optional=True, needs=["ldap3"]),
        "ssh": Collector("ssh", "SSH Checks", _load_auditor("audit_ssh"), _cfg_ssh,
                         optional=True, needs=["paramiko"]),
        "windows_privileges": Collector("windows_privileges", "Windows Checks",
                                        _load_auditor("audit_potato"), _cfg_ssh,
                                        optional=True, needs=["paramiko"]),
        "acl": Collector("acl", "AD Checks", _load_auditor("audit_acl"), _cfg_ssh,
                         optional=True, needs=["paramiko"]),
        "aws": Collector("aws", "AWS Checks", _load_auditor("audit_aws"),
                         lambda: {}, optional=True, needs=["boto3"]),
    }


COLLECTORS = _build_collectors()

# which registry-module collectors correspond to which selectable groups
ALL_COLLECTOR_KEYS = list(COLLECTORS.keys())


def collector_status() -> List[Dict[str, Any]]:
    out = []
    for key, col in COLLECTORS.items():
        available = col.available()
        reason = ""
        if not available:
            reason = "missing library: " + ", ".join(col.needs)
        if key == "aws" and available:
            # AWS also needs credentials to be *usable*; report configured state
            configured = bool(_env("AWS_ACCESS_KEY_ID") or _env("AWS_PROFILE"))
            reason = "" if configured else "AWS credentials not configured"
        out.append({"key": key, "label": col.label, "available": available,
                    "optional": col.optional, "reason": reason})
    return out


# --------------------------------------------------------------------------- #
# Asset synthesis
# --------------------------------------------------------------------------- #
def _guess_asset_type(host: str, findings: List[Finding]) -> str:
    hay = " ".join(f.category for f in findings).lower()
    if "active directory" in hay or "kerberos" in hay or "ldap" in hay:
        return AssetType.DOMAIN_CONTROLLER.value
    if "linux" in hay:
        return AssetType.LINUX.value
    if "cloud" in hay:
        return AssetType.CLOUD.value
    if "windows" in hay or "smb" in hay or "rdp" in hay:
        return AssetType.WINDOWS_SERVER.value
    return AssetType.UNKNOWN.value


def _build_assets(findings: List[Finding], target: str) -> List[Asset]:
    by_host: Dict[str, List[Finding]] = {}
    for f in findings:
        host = f.asset or f.asset_ip or target or "unknown"
        by_host.setdefault(host, []).append(f)

    assets = []
    for host, fs in by_host.items():
        ports, services, techniques = set(), set(), set()
        for f in fs:
            for m in f.mitre:
                techniques.add(m.technique_id)
            for a in f.affected:
                if ":" in str(a):
                    p = str(a).rsplit(":", 1)[-1]
                    if p.isdigit():
                        ports.add(int(p))
                elif str(a).isdigit():
                    ports.add(int(a))
        score = security_score(fs)["score"]
        assets.append(Asset(
            hostname=host,
            ip=next((f.asset_ip for f in fs if f.asset_ip), ""),
            asset_type=_guess_asset_type(host, fs),
            open_ports=sorted(ports),
            services=sorted(services),
            risk_score=100 - score,
            finding_count=sum(1 for f in fs if f.severity_enum.rank >= 2),
            mitre_techniques=sorted(techniques),
            last_audit=utcnow_iso(),
        ))
    return assets


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
def _notify_audit(run: AuditRun, findings: List[Finding], score: Dict[str, Any]) -> None:
    """Send an SNS alert on a genuine audit event (only if SNS is configured)."""
    try:
        import sys
        src = os.path.dirname(os.path.dirname(__file__))
        if src not in sys.path:
            sys.path.insert(0, src)
        from utils.aws_sns import sns_enabled, send_sns_alert
        if not sns_enabled():
            return
        s = run.summary
        crit, high = s.get("CRITICAL", 0), s.get("HIGH", 0)
        # only alert when there is something worth alerting on
        if crit == 0 and high == 0:
            return
        top = sorted(findings, key=lambda f: -f.severity_enum.rank)[:8]
        lines = [f"[Sentinel] Audit {run.audit_id} — score {score['score']}/100 ({score['grade']})",
                 f"Target: {run.target or 'n/a'}",
                 f"Critical: {crit}  High: {high}  Medium: {s.get('MEDIUM',0)}",
                 "", "Top findings:"]
        for f in top:
            if f.severity_enum.rank >= 3:
                lines.append(f"  - [{f.severity}] {f.title} ({f.asset or '-'})")
        ok, detail = send_sns_alert(
            subject=f"[Sentinel] {crit} critical / {high} high — audit {run.audit_id}",
            message="\n".join(lines))
        get_store().log(run.triggered_by, "sns_alert",
                        f"ok={ok} {('' if ok else detail)[:120]}")
    except Exception as e:  # notifications must never break an audit
        try:
            get_store().log(run.triggered_by, "sns_alert", f"error: {e}")
        except Exception:
            pass


def run_audit(
    modules: Optional[List[str]] = None,
    target: str = "",
    triggered_by: str = "system",
    persist: bool = True,
    progress: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, Any]:
    """Run the selected collectors and return a full result bundle."""
    audit_id = uuid.uuid4().hex[:12]
    run = AuditRun(audit_id=audit_id, target=target or _env("LDAP_HOST", ""),
                   triggered_by=triggered_by)

    selected = modules or ALL_COLLECTOR_KEYS
    findings: List[Finding] = []
    module_status: List[Dict[str, Any]] = []

    def emit(stage: str, state: str):
        if progress:
            try:
                progress(stage, state)
            except Exception:
                pass

    emit("Asset Discovery", "done")
    for key in selected:
        col = COLLECTORS.get(key)
        if not col:
            continue
        emit(col.label, "running")
        if not col.available():
            findings.append(Finding(
                title=f"{col.label} skipped — integration not configured",
                description="Required library missing: " + ", ".join(col.needs),
                severity=Severity.INFO.value, module="collector_diagnostics",
                category="Security Operations", detection_source=key,
                signature=f"{key.upper()}_UNAVAILABLE"))
            module_status.append({"key": key, "status": "unavailable",
                                  "reason": "missing library: " + ", ".join(col.needs)})
            emit(col.label, "skipped")
            continue
        try:
            raw = col.run(target=target)
            normd = normalize(key, raw, asset=run.target, audit_id=audit_id)
            findings.extend(normd)
            module_status.append({"key": key, "status": "ok", "findings": len(normd)})
            emit(col.label, "done")
        except Exception as e:  # never let one collector break the run
            findings.append(Finding(
                title=f"{col.label} error",
                description=str(e), severity=Severity.INFO.value,
                module="collector_diagnostics", category="Security Operations",
                detection_source=key, signature=f"{key.upper()}_ERROR"))
            module_status.append({"key": key, "status": "error", "reason": str(e)})
            emit(col.label, "error")

    emit("MITRE Mapping", "done")
    get_mitre().enrich(findings)

    emit("Risk Calculation", "running")
    comp = evaluate_compliance(findings)
    score = security_score(findings, compliance_penalty=comp["penalty"])
    run.summary = summarize(findings)
    run.security_score = score["score"]
    run.modules_used = [k for k in selected if COLLECTORS.get(k)]
    run.status = "completed"
    run.finished_at = utcnow_iso()
    assets = _build_assets(findings, run.target)
    emit("Risk Calculation", "done")

    if persist:
        emit("Report", "running")
        get_store().save_audit(run, findings, assets)
        get_store().log(triggered_by, "run_audit",
                        f"audit {audit_id}: {len(findings)} findings, score {score['score']}")
        _notify_audit(run, findings, score)
        emit("Report", "done")

    return {
        "audit": run,
        "findings": findings,
        "assets": assets,
        "score": score,
        "compliance": comp,
        "posture": posture(findings),
        "coverage": get_mitre().coverage(findings),
        "attack_paths": build_paths(findings),
        "module_status": module_status,
    }
