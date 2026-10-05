# src/auditors/audit_privilege.py
from typing import List, Dict, Any
from ldap3 import Server, Connection, ALL, SIMPLE
from ldap3.core.exceptions import LDAPException

# Auditer les privilèges dans Active Directory via LDAP
def run(host: str, port: int, domain: str, bind_dn: str, password: str, use_ssl: bool = False) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Déduire le Base DN à partir du domaine
    try:
        base_dn = ",".join([f"DC={part}" for part in domain.split(".") if part])
    except Exception:
        base_dn = None

    if not base_dn:
        return [{
            "check": "AD Privilege Audit",
            "result": "Impossible de déduire le BaseDN à partir du domaine.",
            "severity": "CRIT",
            "recommendation": "Vérifier le format du domaine (ex: corp.local)."
        }]

    try:
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(
            server,
            user=bind_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )
    except LDAPException as e:
        return [{
            "check": "Connexion AD (Privilege)",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Vérifier les identifiants, le pare-feu et la connectivité LDAP."
        }]

    # 1) Membres de Domain Admins
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=group)(cn=Domain Admins))",
        attributes=["member"]
    )
    if conn.entries:
        entry = conn.entries[0]
        members = entry.member.values if "member" in entry else []
        findings.append({
            "check": "Membres de Domain Admins",
            "result": f"{len(members)} membres",
            "severity": "WARN" if len(members) > 5 else "OK",
            "recommendation": "Limiter le groupe 'Domain Admins' au strict minimum."
        })

    # 2) adminCount=1 (comptes protégés par AdminSDHolder)
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(adminCount=1))",
        attributes=["sAMAccountName"]
    )
    protected = [str(e.sAMAccountName) for e in conn.entries]
    findings.append({
        "check": "Comptes protégés par AdminSDHolder",
        "result": ", ".join(protected) if protected else "Aucun",
        "severity": "INFO" if protected else "OK",
        "recommendation": "Revoir régulièrement les comptes ayant adminCount=1."
    })

    # 3) Membres du groupe local Administrators sur les machines cachées
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=group)(cn=Administrators))",
        attributes=["member"]
    )
    if conn.entries:
        entry = conn.entries[0]
        members = entry.member.values if "member" in entry else []
        findings.append({
            "check": "Membres du groupe local Administrators",
            "result": ", ".join(members) if members else "Aucun",
            "severity": "WARN" if len(members) > 5 else "OK",
            "recommendation": "Limiter le groupe 'Administrators' aux comptes réellement nécessaires."
        })

    conn.unbind()
    return findings
