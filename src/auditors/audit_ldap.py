from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
from typing import List, Dict, Any
from dataclasses import dataclass
from ldap3.core.exceptions import LDAPException

# classe Finding pour structurer les résultats de l'audit
@dataclass
class Finding:
    check: str
    result: str
    severity: str
    recommendation: str

# Auditer un serveur LDAP pour des problèmes de sécurité courants
def run(host: str, port: int, use_ssl: bool, bind_dn: str, password: str, base_dn: str = None) -> List[Dict[str, Any]]:
    findings = []

    try:
        # Connexion au serveur LDAP
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
        conn = Connection(
            server,
            user=bind_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=True,
            raise_exceptions=True,
            receive_timeout=20
        )

        # Déterminer le Base DN si non fourni
        if base_dn and base_dn.strip():
            base_dn = base_dn.strip()
        elif "." in host:
            base_dn = ",".join(["DC=" + part for part in host.split(".") if part])
        else:
            base_dn = "DC=example,DC=local"

        print(f"[+] Connected to LDAP server {host}:{port}")
        print(f"[+] Using Base DN: {base_dn}")

        # --- Récupérer tous les objets utilisateur (paged pour éviter les problèmes de récursion) ---
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=user)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "userAccountControl", "pwdLastSet"],
            paged_size=200
        )
        # Convertir les entrées en liste pour traitement
        user_entries = list(conn.entries)
        
        # stocker le nombre total d'utilisateurs
        findings.append({
            "check": "Total user accounts",
            "result": str(len(user_entries)),
            "severity": "OK",
            "recommendation": "Ensure regular review of user accounts."
        })

        # detecter les utilisateurs avec mot de passe qui n'expire jamais
        pwd_never_expires = []
        for entry in user_entries:
            try:
                uac = int(entry.userAccountControl.value)
                if uac & 0x10000:  # PASSWORD_NEVER_EXPIRES
                    pwd_never_expires.append(str(entry.sAMAccountName))
            except Exception:
                continue
        # verifier et enregistrer le resultat
        if pwd_never_expires:
            findings.append({
                "check": "Users with Password Never Expires",
                "result": ", ".join(pwd_never_expires),
                "severity": "WARN",
                "recommendation": "Disable 'Password Never Expires' for these users."
            })
        else:
            # verifier et enregistrer le resultat
            findings.append({
                "check": "Password expiration policy",
                "result": "All users expire passwords normally",
                "severity": "OK",
                "recommendation": "No action required."
            })

        # detecter les comptes désactivés
        disabled = []
        for entry in user_entries:
            try:
                uac = int(entry.userAccountControl.value)
                if uac & 0x2:  # ACCOUNTDISABLE
                    disabled.append(str(entry.sAMAccountName))
            except Exception:
                continue
        # verifier et enregistrer le resultat
        findings.append({
            "check": "Disabled accounts",
            "result": ", ".join(disabled) if disabled else "None",
            "severity": "INFO" if disabled else "OK",
            "recommendation": "Remove or review disabled accounts periodically."
        })

        # compter les groupes
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=["cn"],
            paged_size=200
        )
        # Convertir les entrées en liste pour traitement
        groups = list(conn.entries)
        # enregistrer le resultat
        findings.append({
            "check": "Total groups",
            "result": str(len(groups)),
            "severity": "OK",
            "recommendation": "Review group memberships for least privilege."
        })
        # Déconnexion du serveur LDAP
        conn.unbind()

    except LDAPException as e:
        # Gestion des erreurs de connexion LDAP
        findings.append({
            "check": "LDAP connection error",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Check credentials, firewall, and ensure LDAP port (389/636) is reachable."
        })

    except Exception as e:
        # Gestion des erreurs inattendues
        findings.append({
            "check": "Unexpected error",
            "result": repr(e),
            "severity": "CRIT",
            "recommendation": "Enable debug logs; verify server configuration and Base DN."
        })

    return findings
