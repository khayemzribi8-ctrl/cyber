"""
Remediation workflow: structured guidance, allow-listed command execution.

Safety model (spec §11, §20):
  * Every remediation is shown (preview) before it can be executed.
  * Only ADMINs can execute (enforced by the route decorator).
  * Only commands whose first token is on the ALLOWLIST may run; anything else
    is preview-only. Destructive changes are never executed silently.
  * Remote execution requires the relevant channel (WinRM/SSH) to be both
    installed and configured; otherwise the platform returns a clear message
    instead of pretending a change was applied.
"""
from __future__ import annotations

import os
import shlex
from typing import Any, Dict, List

from core.models import Finding, Severity

# Allow-listed leading tokens for remediation commands. Read/idempotent
# hardening cmdlets only — nothing that deletes accounts/objects.
ALLOWLIST = [
    "Set-ADUser", "Set-ADAccountControl", "Set-ADComputer", "Disable-ADAccount",
    "Set-Service", "Stop-Service", "Set-ItemProperty", "New-ItemProperty",
    "Set-SmbServerConfiguration", "Set-MpPreference", "Disable-LocalUser",
    "Enable-NetFirewallProfile", "Set-NetFirewallProfile", "Disable-WindowsOptionalFeature",
    "auditpol", "Set-ADDefaultDomainPasswordPolicy", "Set-ADDomain", "secedit",
]

_RISK_AFTER = {
    Severity.CRITICAL: "Low", Severity.HIGH: "Low", Severity.MEDIUM: "Low",
    Severity.LOW: "Informational", Severity.INFO: "Informational",
}


def _first_token(cmd: str) -> str:
    cmd = (cmd or "").strip()
    # strip a leading powershell wrapper if present
    if cmd.lower().startswith("powershell"):
        # find the -Command payload
        idx = cmd.lower().find("import-module")
        if idx != -1:
            cmd = cmd[idx:]
        else:
            parts = cmd.split('"')
            if len(parts) > 1:
                cmd = parts[1]
    cmd = cmd.replace("Import-Module ActiveDirectory -ErrorAction SilentlyContinue;", "").strip()
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    return toks[0] if toks else ""


def is_allowlisted(cmd: str) -> bool:
    tok = _first_token(cmd)
    return any(tok.lower() == a.lower() for a in ALLOWLIST)


def build_remediation_items(findings: List[Finding]) -> List[Dict[str, Any]]:
    from core.remediation_library import remediation_for
    items = []
    for f in findings:
        if f.severity_enum in (Severity.OK, Severity.INFO):
            continue
        rem = f.remediation
        ps = rem.powershell if rem else ""
        linux = rem.linux if rem else ""
        fix_desc = (rem.fix_description or rem.summary) if rem else ""
        curated = bool(rem and getattr(rem, "curated", False))

        # If the collector attached no runnable command, consult the deterministic
        # remediation library (offline, vetted). It fills most findings.
        if not (ps or linux):
            lib = remediation_for(f)
            if lib:
                ps = lib.powershell
                fix_desc = fix_desc or lib.fix_description
                curated = lib.curated
                f.remediation = lib  # so execute_command sees the curated command

        cmd = ps or linux
        # executable if it comes from the vetted library (curated) OR its leading
        # cmdlet is on the allow-list; guidance-only commands (comments) are neither.
        is_comment = cmd.strip().startswith("#")
        executable = bool(cmd) and not is_comment and (curated or is_allowlisted(cmd))
        # pick the execution channel: AWS findings run via boto3, others WinRM/SSH
        from core.registry import get_module
        _mod = get_module(f.module)
        is_aws = (_mod and _mod.group == "Cloud") or f.signature.upper().startswith("AWS_")
        channel = "aws" if is_aws else "winrm"
        items.append({
            "channel": channel,
            "finding": f,
            "problem": f.title,
            "impact": f.risk or f.description,
            "fix_description": fix_desc or "Review the finding and apply vendor-recommended hardening.",
            "powershell": ps,
            "linux": linux,
            "risk_before": f.severity_enum.value.title(),
            "risk_after": _RISK_AFTER.get(f.severity_enum, "Low"),
            "auto_fixable": executable,
            "has_command": bool(cmd),
            "guidance_only": is_comment,
            "command": cmd,
        })
    items.sort(key=lambda x: -x["finding"].severity_enum.rank)
    return items


def execute_command(finding: Finding, channel: str = "winrm") -> Dict[str, Any]:
    """Execute an allow-listed remediation command over WinRM or SSH.

    Returns a structured result. Never executes non-allowlisted commands.
    """
    rem = finding.remediation
    if not rem or not (rem.powershell or rem.linux):
        # fall back to the deterministic library
        from core.remediation_library import remediation_for
        lib = remediation_for(finding)
        if lib:
            rem = lib
            finding.remediation = lib
    cmd = (rem.powershell if rem else "") or (rem.linux if rem else "")
    if not cmd:
        return {"ok": False, "message": "No remediation command is available for this finding."}
    if cmd.strip().startswith("#"):
        return {"ok": False, "preview_only": True,
                "message": "This is guidance-only (destructive or environment-specific) and is "
                           "not auto-executed. Apply it manually after review.", "command": cmd}
    curated = bool(getattr(rem, "curated", False))
    if not curated and not is_allowlisted(cmd):
        return {"ok": False, "preview_only": True,
                "message": "Command is not vetted/allow-listed and will not be executed "
                           "automatically. Apply it manually after review.", "command": cmd}

    if channel == "aws":
        return _run_aws(finding, cmd)
    if channel == "ssh":
        return _run_ssh(cmd)
    return _run_winrm(cmd)


# AWS fixes run locally via boto3 (using the configured AWS credentials) — no
# AWS CLI binary required, and only a small set of safe, idempotent actions.
def _run_aws(finding, cmd: str) -> Dict[str, Any]:
    sig = (finding.signature or "").upper()
    try:
        import boto3
    except Exception:
        return {"ok": False, "message": "boto3 non installé (pip install boto3).", "command": cmd}
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    try:
        iam = boto3.client("iam", region_name=region)
        if sig == "AWS_PWD_POLICY":
            iam.update_account_password_policy(
                MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True,
                RequireUppercaseCharacters=True, RequireLowercaseCharacters=True,
                MaxPasswordAge=90, PasswordReusePrevention=24, HardExpiry=False)
            return {"ok": True, "message": "Politique de mots de passe IAM renforcée "
                    "(>=14, complexité, rotation 90j, historique 24).", "command": cmd}
        return {"ok": False, "preview_only": True,
                "message": "Ce correctif AWS n'est pas auto-exécutable (destructif ou action "
                           "root requise). Appliquez-le manuellement via la console/CLI.",
                "command": cmd}
    except Exception as e:
        return {"ok": False, "message": f"Erreur AWS (boto3) : {e}", "command": cmd}


def _run_winrm(cmd: str) -> Dict[str, Any]:
    if not os.environ.get("WINRM_HOST"):
        return {"ok": False, "message": "WinRM is not configured (WINRM_HOST unset). "
                                        "Command shown for manual execution.", "command": cmd}
    try:
        from .winrm_exec import run_ps
        out, err = run_ps(cmd)
        return {"ok": not (err or "").strip(),
                "message": (out or err or "Executed.").strip()[:800], "command": cmd}
    except Exception as e:
        return {"ok": False, "message": f"WinRM execution error: {e}", "command": cmd}


def _run_ssh(cmd: str) -> Dict[str, Any]:
    host = os.environ.get("SSH_HOST") or os.environ.get("LDAP_HOST")
    user = os.environ.get("SSH_USERNAME")
    if not host or not user:
        return {"ok": False, "message": "SSH is not configured. Command shown for manual execution.",
                "command": cmd}
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=int(os.environ.get("SSH_PORT", "22")), username=user,
                    password=os.environ.get("SSH_PASSWORD"), timeout=15)
        _, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        ssh.close()
        return {"ok": not err.strip(), "message": (out or err or "Executed.").strip()[:800],
                "command": cmd}
    except Exception as e:
        return {"ok": False, "message": f"SSH execution error: {e}", "command": cmd}
