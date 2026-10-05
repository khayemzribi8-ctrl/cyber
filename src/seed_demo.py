"""
Seed a clearly-labelled DEMO assessment so the dashboard can be explored
without a live domain.

Run with:  python -m src.seed_demo   (or  python src/seed_demo.py)

Every record produced here is flagged demo=True and the audit is shown with a
"DEMO DATA" badge in the UI. This is representative sample data — it is NOT a
real finding set. Real results only come from the audit engine.
"""
from __future__ import annotations

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.compliance import evaluate as evaluate_compliance          # noqa: E402
from core.engine import _build_assets                                # noqa: E402
from core.models import AuditRun, summarize, utcnow_iso              # noqa: E402
from core.normalize import normalize                                 # noqa: E402
from core.scoring import security_score                              # noqa: E402
from core.store import get_store                                     # noqa: E402

# representative findings, in the legacy collector shape, per collector
_DEMO = {
    "ad": [
        {"check": "Domain Admins membership", "result": "9 comptes", "severity": "WARN",
         "recommendation": "Reduce Domain Admins to the strict minimum (least privilege)."},
        {"check": "Kerberos Pre-Auth désactivé", "result": "svc_legacy, jdoe_admin", "severity": "CRIT",
         "recommendation": "Enable Kerberos pre-authentication to prevent AS-REP roasting.",
         "fix_command_template": "Set-ADAccountControl -Identity 'svc_legacy' -DoesNotRequirePreAuth $false"},
        {"check": "Password Never Expires", "result": "svc_backup, svc_sql, kiosk01", "severity": "WARN",
         "recommendation": "Disable 'password never expires' on human/service accounts.",
         "fix_command_template": "Set-ADUser -Identity 'svc_backup' -PasswordNeverExpires $false"},
        {"check": "Comptes inactifs (> 90 jours)", "result": "temp_intern, oldadmin, test01", "severity": "WARN",
         "recommendation": "Disable or remove stale accounts per lifecycle policy."},
        {"check": "Comptes désactivés", "result": "Guest, krbtgt", "severity": "INFO",
         "recommendation": "Review disabled accounts periodically."},
    ],
    "kerberos": [
        {"check": "Comptes Kerberoastables (SPN définis)", "result": "svc_sql, svc_web, svc_report", "severity": "WARN",
         "recommendation": "Use strong, unique passwords / gMSA for SPN accounts."},
        {"check": "Ordinateurs avec délégation non contrainte (unconstrained)", "result": "APPSRV01$", "severity": "CRIT",
         "recommendation": "Replace unconstrained delegation with constrained delegation / RBCD."},
    ],
    "ldap": [
        {"check": "LDAP signing not required", "result": "Server accepts unsigned simple binds on 389", "severity": "WARN",
         "recommendation": "Require LDAP signing and enable channel binding to prevent relay."},
        {"check": "Total user accounts", "result": "312", "severity": "OK",
         "recommendation": "Ensure regular review of accounts."},
    ],
    "windows_privileges": [
        {"check": "SeImpersonatePrivilege activé", "result": "Service account holds SeImpersonatePrivilege (Enabled)", "severity": "CRIT",
         "recommendation": "Restrict impersonation privileges to reduce Potato-class escalation."},
        {"check": "Service Spouleur d'impression (Spooler)", "result": "Spooler is Running on DC01", "severity": "WARN",
         "recommendation": "Disable Print Spooler on domain controllers (PrintNightmare).",
         "fix_command_template": "Set-Service -Name Spooler -StartupType Disabled"},
    ],
    "ssh": [
        {"check": "PermitRootLogin", "result": "yes", "severity": "CRIT",
         "recommendation": "Set 'PermitRootLogin no'."},
        {"check": "PasswordAuthentication", "result": "yes", "severity": "WARN",
         "recommendation": "Disable password auth; use key-based authentication."},
        {"check": "Login Banner", "result": "Not configured", "severity": "INFO",
         "recommendation": "Configure a legal login banner."},
    ],
    "aws": [
        {"check": "Utilisateurs IAM sans MFA", "result": "deploy-bot, analytics-svc", "severity": "CRIT",
         "recommendation": "Enforce MFA for all IAM users."},
        {"check": "Utilisateurs IAM avec rôle AdministratorAccess", "result": "ci-runner", "severity": "WARN",
         "recommendation": "Replace AdministratorAccess with least-privilege policies."},
    ],
    "network": [
        {"check": "RDP exposed (tcp/3389)", "result": "RDP reachable on DC01:3389", "severity": "HIGH",
         "signature": "NET_RDP_EXPOSED", "affected": ["10.0.10.5:3389"],
         "recommendation": "Restrict RDP to management networks / VPN; enforce NLA."},
        {"check": "WinRM (HTTP) exposed (tcp/5985)", "result": "WinRM reachable on APPSRV01:5985", "severity": "HIGH",
         "signature": "NET_WINRM_EXPOSED", "affected": ["10.0.10.20:5985"],
         "recommendation": "Restrict WinRM; prefer HTTPS listener and management network."},
        {"check": "SMB exposed (tcp/445)", "result": "SMB reachable on FILESRV01:445", "severity": "MEDIUM",
         "signature": "NET_SMB_EXPOSED", "affected": ["10.0.10.30:445"],
         "recommendation": "Restrict SMB and require SMB signing."},
        {"check": "Open TCP ports", "result": "6 reachable services on DC01: 88/Kerberos, 135/MS-RPC, 389/LDAP, 445/SMB, 3389/RDP, 636/LDAPS",
         "severity": "INFO", "signature": "NET_OPEN_PORTS",
         "affected": ["88", "135", "389", "445", "3389", "636"],
         "recommendation": "Reduce exposure via segmentation and host firewall."},
    ],
}

_HOSTS = {
    "ad": "DC01", "kerberos": "DC01", "ldap": "DC01", "windows_privileges": "DC01",
    "ssh": "LNX-JUMP01", "aws": "aws-account", "network": "DC01",
}


def seed() -> str:
    store = get_store()
    audit_id = uuid.uuid4().hex[:12]
    findings = []
    for key, items in _DEMO.items():
        host = _HOSTS.get(key, "")
        findings.extend(normalize(key, items, asset=host, audit_id=audit_id))

    comp = evaluate_compliance(findings)
    score = security_score(findings, compliance_penalty=comp["penalty"])
    run = AuditRun(
        audit_id=audit_id, target="10.0.10.5 (demo lab)",
        modules_used=list(_DEMO.keys()), status="completed",
        finished_at=utcnow_iso(), summary=summarize(findings),
        security_score=score["score"], demo=True, triggered_by="demo-seed",
    )
    assets = _build_assets(findings, run.target)
    store.save_audit(run, findings, assets)
    store.log("demo-seed", "seed_demo", f"{len(findings)} demo findings, score {score['score']}")
    print(f"Seeded DEMO audit {audit_id}: {len(findings)} findings, "
          f"score {score['score']}/{score['grade']}, {len(assets)} assets.")
    return audit_id


if __name__ == "__main__":
    seed()
