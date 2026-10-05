"""
AD policy / domain-hardening collector (LDAP, read-only).

Reads the domain object and a few well-known objects to assess:
  * Default domain password policy (length, complexity, max age, history)
  * Account lockout policy (threshold, duration, observation window)
  * ms-DS-MachineAccountQuota (users adding computers -> RBCD abuse)
  * krbtgt password age (Golden Ticket exposure window)
  * Domain functional level

Feeds the Password Policy, Account Lockout, Domain Controller Security and
Vulnerability Management modules and several compliance controls. Needs ldap3.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

_FUNC_LEVEL = {
    0: "Windows 2000", 1: "Windows 2003 interim", 2: "Windows 2003",
    3: "Windows 2008", 4: "Windows 2008 R2", 5: "Windows 2012",
    6: "Windows 2012 R2", 7: "Windows 2016",
}


def _base_dn(domain: str, base_dn: str = "") -> str:
    if base_dn:
        return base_dn
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def _ival(entry, attr, default=0):
    try:
        return int(entry[attr].value)
    except Exception:
        return default


def _filetime_days_ago(ft: int) -> float:
    """AD 'pwdLastSet'-style FILETIME (100ns since 1601) -> age in days."""
    if not ft:
        return -1
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    dt = epoch.timestamp() + ft / 10_000_000
    return (datetime.now(timezone.utc).timestamp() - dt) / 86400.0


def _interval_days(ft_negative: int) -> float:
    """AD duration attributes are negative 100ns intervals -> positive days."""
    if not ft_negative:
        return 0.0
    return abs(ft_negative) / 10_000_000 / 86400.0


def run(host: str, port: int, domain: str, bind_dn: str, password: str,
        use_ssl: bool = False, base_dn: str = "", **_ignored) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE, BASE, SIMPLE
        from ldap3.core.exceptions import LDAPException
    except Exception as e:
        return [{"check": "Policy audit error", "result": f"ldap3 not available: {e}",
                 "severity": "INFO", "recommendation": "Install ldap3 to enable this collector."}]

    bdn = _base_dn(domain, base_dn)
    try:
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
        conn = Connection(server, user=bind_dn, password=password,
                          authentication=SIMPLE, auto_bind=True, receive_timeout=20)
    except LDAPException as e:
        return [{"check": "AD policy connection error", "result": str(e), "severity": "CRIT",
                 "recommendation": "Verify DC reachability, credentials and LDAP port."}]

    # --- domain object ----------------------------------------------------- #
    conn.search(bdn, "(objectClass=domain)", search_scope=BASE,
                attributes=["minPwdLength", "pwdProperties", "maxPwdAge", "minPwdAge",
                            "pwdHistoryLength", "lockoutThreshold", "lockoutDuration",
                            "lockOutObservationWindow", "ms-DS-MachineAccountQuota",
                            "msDS-Behavior-Version"])
    if not conn.entries:
        conn.unbind()
        return [{"check": "AD policy read", "result": "Could not read the domain object.",
                 "severity": "INFO", "recommendation": "Check the base DN / permissions."}]
    d = conn.entries[0]

    min_len = _ival(d, "minPwdLength")
    pwd_props = _ival(d, "pwdProperties")
    complexity = bool(pwd_props & 0x1)
    max_age = _interval_days(_ival(d, "maxPwdAge"))
    history = _ival(d, "pwdHistoryLength")
    lockout_threshold = _ival(d, "lockoutThreshold")
    lockout_duration = _interval_days(_ival(d, "lockoutDuration")) * 24 * 60  # minutes
    maq = _ival(d, "ms-DS-MachineAccountQuota", -1)
    func = _ival(d, "msDS-Behavior-Version", -1)

    # password length (CIS: >= 14)
    findings.append({
        "check": "Password policy: minimum length",
        "signature": "PWD_POLICY_LENGTH",
        "result": f"Minimum password length = {min_len}",
        "severity": "OK" if min_len >= 14 else ("WARN" if min_len >= 8 else "CRIT"),
        "recommendation": "Set a minimum password length of at least 14 characters (CIS)."})
    # complexity
    findings.append({
        "check": "Password policy: complexity",
        "signature": "PWD_POLICY_COMPLEXITY",
        "result": "Complexity enabled" if complexity else "Complexity DISABLED",
        "severity": "OK" if complexity else "CRIT",
        "recommendation": "Enable password complexity requirements."})
    # max age
    findings.append({
        "check": "Password policy: maximum age",
        "signature": "PWD_POLICY_MAXAGE",
        "result": f"Maximum password age = {max_age:.0f} days" + (" (never expires)" if max_age == 0 else ""),
        "severity": "WARN" if (max_age == 0 or max_age > 365) else "OK",
        "recommendation": "Set a sensible maximum password age (e.g. <= 365 days)."})
    # history
    findings.append({
        "check": "Password policy: history length",
        "signature": "PWD_POLICY_HISTORY",
        "result": f"Password history = {history}",
        "severity": "OK" if history >= 12 else "WARN",
        "recommendation": "Remember at least 12 previous passwords (CIS)."})
    # lockout
    if lockout_threshold == 0:
        findings.append({
            "check": "Account lockout policy",
            "signature": "ACCOUNT_LOCKOUT",
            "result": "Account lockout threshold = 0 (accounts NEVER lock out)",
            "severity": "WARN",
            "recommendation": "Set a lockout threshold (e.g. <= 5) to slow password spraying."})
    else:
        findings.append({
            "check": "Account lockout policy",
            "signature": "ACCOUNT_LOCKOUT",
            "result": f"Lockout threshold = {lockout_threshold}, duration = {lockout_duration:.0f} min",
            "severity": "OK" if lockout_threshold <= 10 else "WARN",
            "recommendation": "Keep a reasonable lockout threshold and duration."})
    # machine account quota
    if maq is not None and maq > 0:
        findings.append({
            "check": "Machine Account Quota (ms-DS-MachineAccountQuota)",
            "result": f"ms-DS-MachineAccountQuota = {maq} (any user can join up to {maq} computers)",
            "severity": "WARN",
            "signature": "AD_MACHINE_ACCOUNT_QUOTA",
            "recommendation": "Set ms-DS-MachineAccountQuota to 0 to prevent RBCD / abuse."})
    # functional level
    findings.append({
        "check": "Domain functional level",
        "signature": "AD_FUNCTIONAL_LEVEL",
        "result": _FUNC_LEVEL.get(func, f"level {func}"),
        "severity": "WARN" if (func != -1 and func < 5) else "OK",
        "recommendation": "Raise the domain functional level to a supported version."})

    # --- krbtgt password age (Golden Ticket window) ------------------------ #
    try:
        conn.search(bdn, "(sAMAccountName=krbtgt)", search_scope=SUBTREE,
                    attributes=["pwdLastSet"])
        if conn.entries:
            age = _filetime_days_ago(_ival(conn.entries[0], "pwdLastSet"))
            if age >= 0:
                findings.append({
                    "check": "krbtgt account password age",
                    "result": f"krbtgt password last set {age:.0f} days ago",
                    "severity": "WARN" if age > 180 else "OK",
                    "signature": "AD_KRBTGT_STALE",
                    "recommendation": ("Rotate the krbtgt password twice (per guidance) if it "
                                       "is older than ~180 days to limit Golden Ticket validity.")})
    except LDAPException:
        pass

    conn.unbind()
    return findings
