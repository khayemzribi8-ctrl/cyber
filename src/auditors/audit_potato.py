# src/auditors/audit_potato.py
from typing import List, Dict, Any
import paramiko

# Vérifie l’exposition aux attaques de type Potato via SSH
def run(host: str, port: int, username: str, password: str = None, key_path: str = None) -> List[Dict[str, Any]]:
    """
    Vérifie rapidement l’exposition aux attaques de type *Potato* :
    - SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
    - Service Spouleur d’impression actif
    """
    findings: List[Dict[str, Any]] = []

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_path:
            key = paramiko.RSAKey.from_private_key_file(key_path.strip())
            ssh.connect(hostname=host, port=port, username=username, pkey=key, timeout=10)
        else:
            ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10)

        # 1) Privileges
        cmd_priv = "whoami /priv"
        stdin, stdout, stderr = ssh.exec_command(cmd_priv)
        priv_out = stdout.read().decode(errors="ignore")

        if "SeImpersonatePrivilege" in priv_out and "Enabled" in priv_out:
            findings.append({
                "check": "SeImpersonatePrivilege activé",
                "result": "SeImpersonatePrivilege est activé pour cet utilisateur/service.",
                "severity": "CRIT",
                "recommendation": "Limiter les comptes disposant de SeImpersonatePrivilege pour réduire la surface Potato."
            })

        if "SeAssignPrimaryTokenPrivilege" in priv_out and "Enabled" in priv_out:
            findings.append({
                "check": "SeAssignPrimaryTokenPrivilege activé",
                "result": "SeAssignPrimaryTokenPrivilege est activé.",
                "severity": "WARN",
                "recommendation": "Limiter l’usage de SeAssignPrimaryTokenPrivilege."
            })

        if not any("SeImpersonatePrivilege" in f["check"] for f in findings):
            findings.append({
                "check": "Privileges d’usurpation",
                "result": "Aucun privilège critique (SeImpersonate) activé détecté pour whoami.",
                "severity": "OK",
                "recommendation": "Continuer à restreindre les privilèges sensibles."
            })

        # 2) Print Spooler
        cmd_spool = 'powershell -NoProfile -Command "Get-Service Spooler | Select-Object Status | Out-String"'
        stdin, stdout, stderr = ssh.exec_command(cmd_spool)
        sp_out = stdout.read().decode(errors="ignore")

        if "Running" in sp_out:
            findings.append({
                "check": "Service Spouleur d’impression (Spooler)",
                "result": "Spooler est en cours d’exécution.",
                "severity": "WARN",
                "recommendation": "Désactiver Spooler sur les serveurs AD/DC si non nécessaire (réduit les attaques PrintNightmare/Spooler)."
            })
        else:
            findings.append({
                "check": "Service Spouleur d’impression",
                "result": "Spooler n’est pas actif.",
                "severity": "OK",
                "recommendation": "Bonne pratique sur les serveurs critiques."
            })

        ssh.close()
    # Gestion des erreurs de connexion/exécution
    except Exception as e:
        findings.append({
            "check": "Potato surface scan error",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Vérifier SSH, PowerShell et les permissions sur le serveur cible."
        })

    return findings
