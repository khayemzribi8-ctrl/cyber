# src/auditors/audit_acl.py
from typing import List, Dict, Any
import paramiko
import re

# Analyser les ACL du groupe Domain Admins via SSH
def run(host: str, port: int, username: str, password: str = None, key_path: str = None) -> List[Dict[str, Any]]:
    """
    Analyse les ACL du groupe Domain Admins en utilisant .NET directement (sans Import-Module ActiveDirectory).
    Détecte les droits excessifs accordés à Everyone, Authenticated Users, Domain Users, etc.
    Fonctionne parfaitement via SSH distant.
    """
    findings: List[Dict[str, Any]] = []

    try:
        # Connexion SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_path and key_path.strip():
            key = paramiko.RSAKey.from_private_key_file(key_path.strip())
            ssh.connect(hostname=host, port=port, username=username, pkey=key, timeout=15)
        else:
            ssh.connect(hostname=host, port=port, username=username, password=password, timeout=15)

        # PowerShell .NET pur — pas besoin du module ActiveDirectory
        ps_cmd = r'''
# Récupérer le DN du groupe Domain Admins
$domainDN = (Get-ADDomain).DistinguishedName
$groupPath = "AD:\CN=Domain Admins,CN=Users,$domainDN"

# Charger le descripteur de sécurité via .NET
$group = [System.DirectoryServices.DirectoryEntry]$groupPath
$sd = $group.ObjectSecurity

# Analyser les ACE
$dangerous = @()
foreach ($ace in $sd.Access) {
    $identity = $ace.IdentityReference.Value
    $rights = $ace.ActiveDirectoryRights
    $type = $ace.AccessControlType

    # Identités à risque
    if ($identity -match "Everyone|Authenticated Users|Domain Users|Utilisateurs du domaine|Tous") {
        if ($type -eq "Allow") {
            $dangerous += "$identity : $rights"
        }
    }
}

if ($dangerous.Count -gt 0) {
    $dangerous -join "`n"
} else {
    "OK: Aucune permission dangereuse détectée sur Domain Admins."
}
'''

        # Exécution sécurisée
        full_cmd = (
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
            "$ErrorActionPreference = 'Stop'; "
            "$ProgressPreference = 'SilentlyContinue'; "
            f"{ps_cmd}"
            "\""
        )

        stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=30)
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()

        ssh.close()

        # Gestion des erreurs
        if error and ("not recognized" in error or "Cannot find" in error or "Access is denied" in error):
            findings.append({
                "check": "Lecture ACL Domain Admins",
                "result": "Impossible d'accéder aux objets AD (droits insuffisants ou WinRM/SSH restreint)",
                "severity": "CRIT",
                "recommendation": "L'utilisateur SSH doit avoir les droits suffisants pour lire les objets AD (membre de Domain Users au minimum)."
            })
            return findings

        # Analyse du résultat
        if "OK:" in output:
            findings.append({
                "check": "ACL Domain Admins",
                "result": "Aucune ACE dangereuse (Everyone, Authenticated Users, etc.) détectée.",
                "severity": "OK"
            })
        elif output.strip():
            findings.append({
                "check": "ACL dangereuse sur Domain Admins",
                "result": output.strip(),
                "severity": "CRIT",
                "recommendation": "Supprimer immédiatement les droits accordés à Everyone / Authenticated Users / Domain Users sur le groupe Domain Admins."
            })
        else:
            findings.append({
                "check": "ACL Domain Admins",
                "result": "Aucun résultat retourné (possible erreur silencieuse).",
                "severity": "WARN"
            })

    except paramiko.AuthenticationException:
        findings.append({
            "check": "Connexion SSH",
            "result": "Échec d'authentification SSH",
            "severity": "CRIT",
            "recommendation": "Vérifier les identifiants SSH."
        })
    except paramiko.SSHException as e:
        findings.append({
            "check": "Connexion SSH",
            "result": f"Erreur SSH : {str(e)}",
            "severity": "CRIT",
            "recommendation": "Vérifier la connectivité et le service SSH sur la cible."
        })
    except Exception as e:
        findings.append({
            "check": "ACL Scan error",
            "result": f"Exception inattendue : {str(e)}",
            "severity": "CRIT",
            "recommendation": "Vérifier les logs et la configuration."
        })

    return findings