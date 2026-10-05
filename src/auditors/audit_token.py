# src/auditors/audit_token.py
from typing import List, Dict, Any
from ldap3 import Server, Connection, ALL, SIMPLE
from ldap3.core.exceptions import LDAPException

# Auditer les configurations de token/Kerberos dans Active Directory via LDAP
def run(host: str, port: int, domain: str, bind_dn: str, password: str, use_ssl: bool = False) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        base_dn = ",".join([f"DC={part}" for part in domain.split(".") if part])
    except Exception:
        base_dn = None

    if not base_dn:
        return [{
            "check": "Token/Kerberos",
            "result": "Impossible de déduire le BaseDN.",
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
            "check": "Connexion AD (Token)",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Vérifier les identifiants et la connectivité AD."
        }]

    # 1) Comptes Kerberoastables (SPN définis)
    #    On exclut les comptes machine (objectCategory=computer) et krbtgt :
    #    seuls les comptes de service "utilisateur" avec SPN sont réellement
    #    Kerberoastables de façon pertinente.
    conn.search(
        search_base=base_dn,
        search_filter="(&(servicePrincipalName=*)(objectCategory=person)(!(sAMAccountName=krbtgt)))",
        attributes=["sAMAccountName", "servicePrincipalName"]
    )
    kerb = [str(e.sAMAccountName) for e in conn.entries]
    findings.append({
        "check": "Comptes Kerberoastables (SPN définis)",
        "result": ", ".join(kerb) if kerb else "Aucun",
        "severity": "WARN" if kerb else "OK",
        "recommendation": "Utiliser des mots de passe robustes et uniquement des comptes de service dédiés pour les SPN."
    })

    # 2) Délégation non contrainte (Unconstrained delegation)
    #    On EXCLUT les contrôleurs de domaine (SERVER_TRUST_ACCOUNT = 8192) :
    #    les DC sont "trusted for delegation" par conception ; les signaler
    #    serait un faux positif. Seuls les serveurs NON-DC sont réellement à risque.
    conn.search(
        search_base=base_dn,
        search_filter=("(&(objectClass=computer)"
                       "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                       "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"),
        attributes=["sAMAccountName"]
    )
    unconstrained = [str(e.sAMAccountName) for e in conn.entries]
    findings.append({
        "check": "Ordinateurs avec délégation non contrainte (unconstrained)",
        "result": ", ".join(unconstrained) if unconstrained else "Aucun",
        "severity": "CRIT" if unconstrained else "OK",
        "recommendation": "Éviter la délégation non contrainte, préférer la délégation contrainte ou RBCD."
    })

    # 3) Constrained delegation (info only)
    conn.search(
        search_base=base_dn,
        search_filter="(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        attributes=["sAMAccountName"]
    )
    constrained = [str(e.sAMAccountName) for e in conn.entries]
    findings.append({
        "check": "Objets avec délégation configurée (constrained/RBCD)",
        "result": ", ".join(constrained) if constrained else "Aucun",
        "severity": "INFO",
        "recommendation": "Revoir la délégation et appliquer le principe du moindre privilège."
    })

    conn.unbind()
    return findings
