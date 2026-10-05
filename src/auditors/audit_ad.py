
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
from ldap3.core.exceptions import LDAPException
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Auditer une forêt Active Directory via LDAP
def run(host: str, port: int, domain: str, bind_dn: str, password: str) -> List[Dict[str, Any]]:
    findings = []

    # extraction du Base DN a partir du nom de domaine
    try:
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
    except Exception:
        base_dn = None

    # verifier si le base DN est valide
    if not base_dn:
        return [{
            "check": "Active Directory",
            "result": "Impossible de déterminer le Base DN",
            "severity": "CRIT",
            "recommendation": "Format de domaine incorrect (ex: corp.local)."
        }]

    # connexion au serveur AD
    try:
        server = Server(host, port=port, get_info=ALL, connect_timeout=10)

        conn = Connection(
            server,
            user=bind_dn,        
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )
    # gestion des erreurs de connexion ldap
    except LDAPException as e:
        return [{
            "check": "AD connection",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Vérifier IP du DC, identifiants, port (389/636), firewall."
        }]

    # debut des audits
    privileged_groups = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Backup Operators",
        "Account Operators"
    ]

    # verifier les membres des groupes privilegies
    for group in privileged_groups:
        conn.search(
            search_base=base_dn,
            search_filter=f"(cn={group})",
            attributes=["member"]
        )

        # verifier si le groupe existe
        if not conn.entries:
            findings.append({
                "check": f"Groupe {group}",
                "result": "Groupe introuvable",
                "severity": "INFO",
                "recommendation": "Vérifier si le groupe existe dans cette forêt AD."
            })
            continue
        # recuperer les membres du groupe
        entry = conn.entries[0]
        members = entry.member.values if "member" in entry else []
        count = len(members)

        # enregistrer le resultat
        findings.append({
            "check": f"{group} membership",
            "result": f"{count} comptes",
            "severity": "WARN" if count > 5 else "OK",
            "recommendation": "Limiter les comptes privilégiés → Principe du moindre privilège."
        })

   # uac 2 correspond a "compte désactivé"
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        attributes=["sAMAccountName"]
    )

    # recuperer les comptes désactivés
    disabled = [str(e.sAMAccountName) for e in conn.entries]

    # enregistrer le resultat
    findings.append({
        "check": "Comptes désactivés",
        "result": ", ".join(disabled) if disabled else "Aucun",
        "severity": "INFO",
        "recommendation": "Supprimer les comptes désactivés non nécessaires."
    })

    # rechercher les mot de passe qui n'expirent jamais
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        attributes=["sAMAccountName"]
    )

    # recuperer les comptes avec mot de passe qui n'expire jamais
    pne = [str(e.sAMAccountName) for e in conn.entries]

    # enregistrer le resultat
    findings.append({
        "check": "Password Never Expires",
        "result": ", ".join(pne) if pne else "Tous expirent correctement",
        "severity": "WARN" if pne else "OK",
        "recommendation": "Désactiver 'PasswordNeverExpires'."
    })

    # rechercher les comptes sans date d'expiration
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(accountExpires=9223372036854775807))",
        attributes=["sAMAccountName"]
    )

    # recuperer les comptes sans date d'expiration
    non_expiring = [str(e.sAMAccountName) for e in conn.entries]

    # enregistrer le resultat
    findings.append({
        "check": "Compte sans expiration",
        "result": f"{len(non_expiring)} comptes détectés",
        "severity": "WARN",
        "affected": non_expiring,
        "fix_command_template": "Set-ADUser -Identity {USERNAME} -AccountExpirationDate (Get-Date).AddDays(30)"
    })
    
    # rechercher les comptes avec Kerberos Pre-Auth désactivé
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        attributes=["sAMAccountName"]
    )

    # recuperer les comptes avec Kerberos Pre-Auth désactivé
    nopreauth = [str(e.sAMAccountName) for e in conn.entries]

    # enregistrer le resultat
    findings.append({
        "check": "Kerberos Pre-Auth désactivé",
        "result": ", ".join(nopreauth) if nopreauth else "Aucun",
        "severity": "CRIT" if nopreauth else "OK",
        "recommendation": "Activer Kerberos Pre-Auth pour éviter AS-REP Roasting."
    })

    # rechercher les comptes inactifs depuis plus de 90 jours
    def datetime_to_filetime(dt: datetime) -> int:
        FILETIME_EPOCH = datetime(1601, 1, 1)
        delta = dt - FILETIME_EPOCH
        return int(delta.total_seconds() * 10_000_000)

    # calculer le timestamp pour 90 jours
    threshold_date = datetime.now() - timedelta(days=90)
    threshold_filetime = datetime_to_filetime(threshold_date)
    
    
    conn.search(
        search_base=base_dn,
        search_filter=f"(&(objectClass=user)(lastLogonTimestamp<={threshold_filetime}))",
        attributes=["sAMAccountName", "lastLogonTimestamp"]
    )
    
    # recuperer les comptes inactifs depuis plus de 90 jours
    stale = [str(e.sAMAccountName) for e in conn.entries]

    # enregistrer le resultat
    findings.append({
        "check": "Comptes inactifs (> 90 jours)",
        "result": ", ".join(stale) if stale else "Aucun",
        "severity": "WARN" if stale else "OK",
        "recommendation": "Désactiver les comptes inactifs ou appliquer une politique lifecycle."
    })


    conn.unbind()
    return findings
