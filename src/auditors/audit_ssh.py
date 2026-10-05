# src/auditors/audit_ssh.py
import paramiko
import re
from typing import List, Dict, Any
from dataclasses import dataclass
# classe pour structurer les résultats de l'audit
@dataclass
class Finding:
    check: str
    result: str
    severity: str
    recommendation: str

# Auditer un serveur SSH pour des problèmes de configuration courants
def run(host: str, port: int, username: str, password: str = None, key_path: str = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        # établir la connexion SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # choisir la méthode d'authentification
        if key_path and key_path.strip():
            print(f"[+] Using SSH key: {key_path}")
            key = paramiko.RSAKey.from_private_key_file(key_path.strip())
            # authentification par clé
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=key,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
        else:
            # authentification par mot de passe
            print(f"[+] Connecting with username/password: {username}")
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )

        print(f"[+] Connected to SSH on {host}:{port}")

        # essayer de lire le fichier sshd_config
        commands_to_try = [
            'cmd /c type "C:\\ProgramData\\ssh\\sshd_config"', 
            'powershell -NoProfile -NonInteractive -Command "Get-Content -Path C:\\ProgramData\\ssh\\sshd_config -ErrorAction SilentlyContinue"'
        ]

        # initialiser les variables
        config = ""
        last_err = ""
        succeeded_cmd = None

        # essayer chaque commande jusqu'à ce qu'une réussisse
        for c in commands_to_try:
            stdin, stdout, stderr = ssh.exec_command(c)
            out_bytes = stdout.read()
            err_bytes = stderr.read()
            out = out_bytes.decode("utf-8", errors="ignore")
            err = err_bytes.decode("utf-8", errors="ignore")

            print(f"[DEBUG] tried cmd: {c}")
            print(f"[DEBUG] stdout length={len(out_bytes)} stderr length={len(err_bytes)}")
            if err:
                print(f"[DEBUG] stderr preview: {err.strip()[:200]}")

            if out.strip():
                config = out
                succeeded_cmd = c
                break
            else:
                last_err = err or last_err

        print(f"[DEBUG] selected_cmd={succeeded_cmd}")

        # si aucune commande n'a réussi, enregistrer une erreur
        if not config.strip():
            findings.append({
                "check": "sshd_config access",
                "result": "Could not read sshd_config",
                "severity": "CRIT",
                "recommendation": "Ensure user has read permissions or create a temporary readable copy of sshd_config in C:\\Users\\Public for auditing."
            })
            ssh.close()
            return findings

        # fonction utilitaire pour extraire les paramètres 
        def match_param(param, default=None):
            pattern = re.compile(rf'^{param}\s+(.*)', re.IGNORECASE | re.MULTILINE)
            m = pattern.search(config)
            return m.group(1).strip() if m else default

        #Effectuer les vérifications clés 
        permit_root = match_param("PermitRootLogin", "prohibit-password")
        
        # Vérification des paramètres de sécurité
        findings.append({
            "check": "PermitRootLogin",
            "result": permit_root,
            "severity": "CRIT" if permit_root.lower() != "no" and permit_root.lower() != "prohibit-password" else "OK",
            "recommendation": "Set 'PermitRootLogin no' to disable remote root login."
        })

        # Vérification de l'authentification par mot de passe
        password_auth = match_param("PasswordAuthentication", "yes")
        findings.append({
            "check": "PasswordAuthentication",
            "result": password_auth,
            "severity": "WARN" if password_auth.lower() != "no" else "OK",
            "recommendation": "Disable password authentication; use key-based authentication."
        })
        # Vérification de la version du protocole SSH

        protocol = match_param("Protocol", "2")
        findings.append({
            "check": "SSH Protocol Version",
            "result": protocol,
            "severity": "OK" if protocol == "2" else "CRIT",
            "recommendation": "Use Protocol 2 only."
        })
        # Vérification du transfert X11

        x11 = match_param("X11Forwarding", "no")
        if x11.lower() == "yes":
            findings.append({
                "check": "X11Forwarding",
                "result": "enabled",
                "severity": "WARN",
                "recommendation": "Disable X11Forwarding unless required."
            })

        # Vérification de la configuration de la bannière de connexion
        banner_pattern = re.compile(r'^\s*Banner\s+(.*)', re.IGNORECASE | re.MULTILINE)
        match_block_pattern = re.compile(r'^Match\s+User\s+(\S+).*?Banner\s+(.*)', re.IGNORECASE | re.MULTILINE | re.DOTALL)

        # Recherche de toute directive Banner
        banner_matches = banner_pattern.findall(config)
        user_banner_matches = match_block_pattern.findall(config)

        # Enregistrer les résultats de la bannière
        if user_banner_matches:
            for user, path in user_banner_matches:
                findings.append({
                    "check": f"Login Banner (User: {user})",
                    "result": path.strip(),
                    "severity": "OK",
                    "recommendation": f"Personalized banner configured for user '{user}'."
                })
        # Vérification de la bannière globale
        elif banner_matches:
            findings.append({
                "check": "Login Banner",
                "result": banner_matches[0].strip(),
                "severity": "OK",
                "recommendation": "Banner is configured globally."
            })
        # Aucune bannière configurée
        else:
            findings.append({
                "check": "Login Banner",
                "result": "Not configured",
                "severity": "INFO",
                "recommendation": "Configure a legal login banner for security compliance."
            })

        # fermer la connexion SSH
        ssh.close()

    # gérer les exceptions de connexion SSH
    except Exception as e:
        findings.append({
            "check": "SSH connection error",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": "Verify credentials, network, and SSH access permissions."
        })

    return findings
