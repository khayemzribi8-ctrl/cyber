"""
Windows host collector over WinRM (PowerShell).

Uses WinRM (5985/5986) — which is typically already enabled on a DC via
Enable-PSRemoting — to run a single read-only PowerShell script that returns a
JSON snapshot of the host security configuration. From that snapshot it builds
findings for the Windows/host modules (firewall, Defender, SMBv1, SMB signing,
Print Spooler, PowerShell v2, RDP NLA, local admins, Guest account,
command-line auditing, LSA protection).

Requires the optional ``pywinrm`` package. Authentication uses NTLM so domain
credentials work out of the box. Nothing is modified on the target — every
command is read-only.

Set in .env:
    WINRM_HOST=<DC ip>
    WINRM_USERNAME=CYBERLAB\\Administrator   (DOMAIN\\user is most reliable for NTLM)
    WINRM_PASSWORD=<password>
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

# read-only PowerShell snapshot; pywinrm base64-encodes this, so quoting is safe
_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
try { $r.os=(Get-CimInstance Win32_OperatingSystem).Caption } catch {}
try { $r.firewall=@(Get-NetFirewallProfile | ForEach-Object { @{ name="$($_.Name)"; enabled=[bool]$_.Enabled } }) } catch {}
try { $mp=Get-MpComputerStatus; $r.defender=@{ realtime=[bool]$mp.RealTimeProtectionEnabled; av=[bool]$mp.AntivirusEnabled; tamper=[bool]$mp.IsTamperProtected } } catch { $r.defender=$null }
try { $sc=Get-SmbServerConfiguration; $r.smb1=[bool]$sc.EnableSMB1Protocol; $r.smb_signing=[bool]$sc.RequireSecuritySignature } catch {}
try { $r.spooler="$((Get-Service Spooler).Status)" } catch {}
try { $r.psv2="$((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State)" } catch {}
try { $r.rdp_nla=[int](Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication } catch {}
try { $r.rdp_enabled=([int](Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections -eq 0) } catch {}
try { $r.local_admins=@(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { "$($_.Name)" }) } catch {}
try { $r.guest_enabled=[bool](Get-LocalUser -Name 'Guest').Enabled } catch {}
try { $r.lsa_ppl=[int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL).RunAsPPL } catch {}
try { $r.cmdline_audit=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled).ProcessCreationIncludeCmdLine_Enabled } catch {}
$r | ConvertTo-Json -Depth 5 -Compress
"""


def _f(check, result, severity, signature="", affected=None, rec=""):
    d = {"check": check, "result": result, "severity": severity, "recommendation": rec}
    if signature:
        d["signature"] = signature
    if affected:
        d["affected"] = affected
    return d


def run(host: str, username: str = "", password: str = "", port: int = 5985,
        transport: str = "ntlm", **_ignored) -> List[Dict[str, Any]]:
    if not host:
        return [_f("WinRM audit", "No WINRM_HOST configured.", "INFO",
                   rec="Set WINRM_HOST/USERNAME/PASSWORD in .env.")]
    try:
        import winrm  # optional dependency
    except Exception as e:
        return [_f("Windows WinRM audit error", f"pywinrm not available: {e}", "INFO",
                   rec="pip install pywinrm to enable the WinRM host collector.")]

    try:
        scheme = "https" if int(port) == 5986 else "http"
        session = winrm.Session(f"{scheme}://{host}:{port}/wsman",
                                auth=(username, password), transport=transport,
                                server_cert_validation="ignore")
        res = session.run_ps(_PS)
        out = res.std_out.decode("utf-8", errors="ignore").strip()
        err = res.std_err.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        return [_f("Windows WinRM connection error",
                   f"Unable to connect to WinRM on {host}:{port} — {e}", "CRIT",
                   rec="Verify WinRM is enabled (Enable-PSRemoting), reachable, and that "
                       "WINRM_USERNAME is DOMAIN\\user with NTLM.")]

    if not out:
        return [_f("Windows WinRM audit", f"No data returned. {err[:200]}", "CRIT",
                   rec="Check WinRM permissions and that the account can run PowerShell.")]

    try:
        data = json.loads(out)
    except Exception:
        return [_f("Windows WinRM audit", f"Unparseable response: {out[:200]}", "INFO",
                   rec="Unexpected WinRM output.")]

    findings: List[Dict[str, Any]] = []
    osname = data.get("os", "Windows host")
    findings.append(_f("Windows host audited", f"{osname} via WinRM on {host}", "OK"))

    # firewall
    fw = data.get("firewall") or []
    disabled = [p.get("name") for p in fw if not p.get("enabled")]
    if disabled:
        findings.append(_f("Windows Firewall profile disabled",
                           "Disabled profiles: " + ", ".join(disabled), "WARN",
                           "WIN_FIREWALL", disabled,
                           "Enable the Windows Defender Firewall on all profiles."))
    elif fw:
        findings.append(_f("Windows Firewall", "All profiles enabled", "OK"))

    # defender
    dfn = data.get("defender")
    if isinstance(dfn, dict):
        if not dfn.get("realtime"):
            findings.append(_f("Windows Defender real-time protection disabled",
                               "RealTimeProtectionEnabled = False", "WARN", "WIN_DEFENDER",
                               rec="Enable real-time protection / endpoint protection."))
        if not dfn.get("tamper"):
            findings.append(_f("Windows Defender tamper protection off",
                               "IsTamperProtected = False", "INFO", "WIN_DEFENDER",
                               rec="Enable tamper protection where supported."))
        if dfn.get("realtime") and dfn.get("tamper"):
            findings.append(_f("Windows Defender", "Real-time + tamper protection enabled", "OK"))

    # SMBv1
    if data.get("smb1") is True:
        findings.append(_f("SMBv1 protocol enabled",
                           "EnableSMB1Protocol = True (legacy, exploitable)", "CRIT",
                           "SMBV1_ENABLED", rec="Disable SMBv1 (Remove/Disable SMB1Protocol)."))
    elif data.get("smb1") is False:
        findings.append(_f("SMBv1 protocol", "Disabled", "OK"))

    # SMB signing
    if data.get("smb_signing") is False:
        findings.append(_f("SMB signing not required",
                           "RequireSecuritySignature = False (relay risk)", "WARN",
                           "SMB_SIGNING", rec="Require SMB signing to prevent relay attacks."))
    elif data.get("smb_signing") is True:
        findings.append(_f("SMB signing", "Required", "OK"))

    # spooler
    sp = str(data.get("spooler", ""))
    if sp == "Running":
        findings.append(_f("Print Spooler service running",
                           "Spooler = Running", "WARN", "WIN_SPOOLER",
                           rec="Disable the Print Spooler on servers/DCs (PrintNightmare)."))
    elif sp:
        findings.append(_f("Print Spooler service", sp, "OK"))

    # PowerShell v2
    if str(data.get("psv2", "")).lower() == "enabled":
        findings.append(_f("Legacy PowerShell v2 enabled",
                           "MicrosoftWindowsPowerShellV2Root = Enabled", "WARN", "PSV2",
                           rec="Remove Windows PowerShell 2.0 (downgrade/logging bypass)."))

    # RDP NLA
    if data.get("rdp_enabled") and data.get("rdp_nla") is not None and int(data.get("rdp_nla")) != 1:
        findings.append(_f("RDP without Network Level Authentication",
                           "UserAuthentication = 0 (NLA not enforced)", "WARN", "RDP_NLA",
                           rec="Enforce NLA for RDP (UserAuthentication = 1)."))

    # local admins
    admins = data.get("local_admins") or []
    if admins:
        sev = "WARN" if len(admins) > 5 else "INFO"
        findings.append(_f("Local Administrators membership",
                           f"{len(admins)} members: " + ", ".join(admins[:15]), sev,
                           "LOCAL_ADMINS", admins,
                           "Review local Administrators; use LAPS for local admin passwords."))

    # guest
    if data.get("guest_enabled") is True:
        findings.append(_f("Guest account enabled", "Guest account is enabled", "WARN",
                           "GUEST_ENABLED", rec="Disable the built-in Guest account."))

    # command-line auditing
    if data.get("cmdline_audit") is not None and int(data.get("cmdline_audit")) != 1:
        findings.append(_f("Command-line process auditing disabled",
                           "ProcessCreationIncludeCmdLine_Enabled != 1", "INFO", "CMDLINE_AUDIT",
                           rec="Enable command-line auditing for process-creation events (4688)."))

    # LSA protection
    if data.get("lsa_ppl") is not None and int(data.get("lsa_ppl")) != 1:
        findings.append(_f("LSASS not running as Protected Process (PPL)",
                           "RunAsPPL != 1", "INFO", "LSA_PPL",
                           rec="Enable LSA protection (RunAsPPL) to hinder credential dumping."))

    return findings
