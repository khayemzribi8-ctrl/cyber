"""
ADCS / PKI collector (LDAP, read-only).

Enumerates the Active Directory Certificate Services objects stored in the
Configuration partition and flags the classic escalation misconfigurations
(ESC1 / ESC2 / ESC3) that are detectable purely from LDAP attributes — no
exploitation is performed. Requires the same directory reachability/creds as
the AD collector (ldap3).

Detected:
  * ESC1  - template lets the enrollee supply the subject (SAN) AND has a
            client-authentication EKU  -> impersonation of any principal.
  * ESC2  - template has Any-Purpose EKU or no EKU restriction.
  * ESC3  - Certificate Request Agent EKU (enrollment agent).
  * Enrollment Services (issuing CAs) inventory.
"""
from __future__ import annotations

from typing import Any, Dict, List

# EKU OIDs
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.5.2.3.4"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
CLIENT_AUTH_EKUS = {EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON, EKU_PKINIT_CLIENT}

# msPKI-Certificate-Name-Flag
CT_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
# msPKI-Enrollment-Flag
CT_PEND_ALL_REQUESTS = 0x00000002  # manager approval required


def _config_nc(domain: str, base_dn: str = "") -> str:
    if base_dn:
        return f"CN=Configuration,{base_dn}"
    parts = [p for p in domain.split(".") if p]
    return "CN=Configuration," + ",".join(f"DC={p}" for p in parts)


def _ival(entry, attr, default=0):
    try:
        return int(entry[attr].value)
    except Exception:
        return default


def _vals(entry, attr):
    try:
        v = entry[attr].value
        if v is None:
            return []
        return v if isinstance(v, list) else [v]
    except Exception:
        return []


def run(host: str, port: int, domain: str, bind_dn: str, password: str,
        use_ssl: bool = False, base_dn: str = "", **_ignored) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
        from ldap3.core.exceptions import LDAPException
    except Exception as e:
        return [{"check": "ADCS audit error", "result": f"ldap3 not available: {e}",
                 "severity": "INFO", "recommendation": "Install ldap3 to enable the ADCS collector."}]

    config_nc = _config_nc(domain, base_dn)
    pki_base = f"CN=Public Key Services,CN=Services,{config_nc}"
    tmpl_base = f"CN=Certificate Templates,{pki_base}"
    ca_base = f"CN=Enrollment Services,{pki_base}"

    try:
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
        conn = Connection(server, user=bind_dn, password=password,
                          authentication=SIMPLE, auto_bind=True, receive_timeout=20)
    except LDAPException as e:
        return [{"check": "ADCS connection error", "result": str(e), "severity": "CRIT",
                 "recommendation": "Verify DC reachability, credentials and LDAP port."}]

    # --- Enrollment Services (issuing CAs) --------------------------------- #
    cas: List[str] = []
    try:
        conn.search(ca_base, "(objectClass=pKIEnrollmentService)", search_scope=SUBTREE,
                    attributes=["cn", "dNSHostName"])
        for e in conn.entries:
            name = str(e.cn.value) if "cn" in e else "?"
            dns = str(e.dNSHostName.value) if "dNSHostName" in e else ""
            cas.append(f"{name} ({dns})" if dns else name)
    except LDAPException:
        # No ADCS installed / container absent -> report cleanly and stop.
        conn.unbind()
        return [{"check": "ADCS presence", "result": "No Certificate Services (ADCS) found in this forest.",
                 "severity": "OK", "signature": "ADCS_PRESENCE",
                 "recommendation": "No ADCS attack surface detected."}]

    if not cas:
        conn.unbind()
        return [{"check": "ADCS presence", "result": "No issuing CA (Enrollment Services) found.",
                 "severity": "OK", "signature": "ADCS_PRESENCE",
                 "recommendation": "No ADCS attack surface detected."}]

    findings.append({
        "check": "Certificate Authorities (ADCS)",
        "signature": "ADCS_CA_INVENTORY",
        "result": f"{len(cas)} issuing CA(s): " + ", ".join(cas),
        "severity": "INFO", "affected": cas,
        "recommendation": "Inventory of Certificate Authorities. Review CA and template security."})

    # --- Certificate templates -------------------------------------------- #
    try:
        conn.search(tmpl_base, "(objectClass=pKICertificateTemplate)", search_scope=SUBTREE,
                    attributes=["cn", "displayName", "msPKI-Certificate-Name-Flag",
                                "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage"])
        templates = list(conn.entries)
    except LDAPException as e:
        conn.unbind()
        findings.append({"check": "ADCS template read error", "result": str(e),
                         "severity": "INFO", "recommendation": "Could not read certificate templates."})
        return findings

    esc1 = esc2 = esc3 = 0
    for t in templates:
        name = str(t.displayName.value) if "displayName" in t and t.displayName.value else str(t.cn.value)
        name_flag = _ival(t, "msPKI-Certificate-Name-Flag")
        enroll_flag = _ival(t, "msPKI-Enrollment-Flag")
        ekus = set(str(x) for x in _vals(t, "pKIExtendedKeyUsage"))
        supplies_subject = bool(name_flag & CT_ENROLLEE_SUPPLIES_SUBJECT)
        manager_approval = bool(enroll_flag & CT_PEND_ALL_REQUESTS)
        has_client_auth = bool(ekus & CLIENT_AUTH_EKUS) or (EKU_ANY_PURPOSE in ekus) or (not ekus)

        # ESC1: enrollee supplies subject + client-auth EKU + no manager approval
        if supplies_subject and has_client_auth and not manager_approval:
            esc1 += 1
            findings.append({
                "check": f"ADCS ESC1 vulnerable certificate template: {name}",
                "result": (f"Template '{name}' allows the enrollee to supply the subject "
                           f"(SAN) and issues a client-authentication certificate without "
                           f"manager approval. A low-privileged user could request a "
                           f"certificate as any principal (incl. Domain Admin)."),
                "severity": "CRIT",
                "signature": "ADCS_ESC1",
                "affected": [name],
                "recommendation": ("Remove ENROLLEE_SUPPLIES_SUBJECT, require manager approval, "
                                   "or restrict enrollment rights and the EKU on this template.")})
        # ESC2: Any Purpose or no EKU
        elif (EKU_ANY_PURPOSE in ekus or not ekus) and not manager_approval:
            esc2 += 1
            findings.append({
                "check": f"ADCS ESC2 over-permissive template: {name}",
                "result": (f"Template '{name}' has an Any-Purpose (or unrestricted) EKU and no "
                           f"manager approval, allowing broad certificate misuse."),
                "severity": "WARN",
                "signature": "ADCS_ESC2",
                "affected": [name],
                "recommendation": "Restrict the template EKU to only the required purpose(s)."})
        # ESC3: enrollment agent
        if EKU_ENROLLMENT_AGENT in ekus and not manager_approval:
            esc3 += 1
            findings.append({
                "check": f"ADCS ESC3 enrollment agent template: {name}",
                "result": f"Template '{name}' grants the Certificate Request Agent EKU.",
                "severity": "WARN",
                "signature": "ADCS_ESC3",
                "affected": [name],
                "recommendation": "Restrict enrollment-agent templates and their enrollment rights."})

    findings.append({
        "check": "ADCS certificate templates reviewed",
        "signature": "ADCS_TEMPLATES",
        "result": f"{len(templates)} templates reviewed — ESC1: {esc1}, ESC2: {esc2}, ESC3: {esc3}.",
        "severity": "OK" if not (esc1 or esc2 or esc3) else "INFO",
        "recommendation": "Review certificate template security regularly (Certipy/PSPKI)."})

    conn.unbind()
    return findings
