"""
Deterministic remediation library.

Maps findings (by canonical signature, then by keyword) to a known-good,
idempotent hardening command. This is the primary, offline, reliable source of
fix commands — no AI or API key required.

Two classes of entry:
  * ``curated=True``  — safe, idempotent hardening that an ADMIN may EXECUTE from
    the platform (after confirmation). These do not delete accounts/objects.
  * ``curated=False`` — a command is still shown to copy, but it is NOT
    auto-executable because it is destructive or environment-specific
    (e.g. removing group members, scoping a firewall to your networks). It is
    guidance the operator applies manually.

Per-identity fixes are rendered as a small PowerShell loop over the exact
principals in the finding (values that came from AD, never free user input).
"""
from __future__ import annotations

from typing import List, Optional

from .models import Finding, Remediation, Severity


def _loop(identities: List[str], inner: str) -> str:
    """PowerShell loop applying `inner` (uses $_) over the given identities."""
    ids = ", ".join("'" + str(i).replace("'", "") + "'" for i in identities[:60])
    return f"@({ids}) | ForEach-Object {{ {inner} }}"


def _strip_dollar(name: str) -> str:
    return str(name).rstrip("$")


# each rule: (matcher, builder) -> Remediation
# matcher checks signature (upper) and/or keywords in the title (lower)
def remediation_for(finding: Finding) -> Optional[Remediation]:
    sig = (finding.signature or "").upper()
    title = (finding.title or "").lower()
    aff = [a for a in (finding.affected or []) if a and str(a).lower() not in
           ("none", "aucun", "tous expirent correctement")]

    def R(ps, curated=True, desc="", risk_after="Low", rollback=""):
        return Remediation(
            summary=desc or finding.title,
            fix_description=desc or (finding.remediation.fix_description
                                     if finding.remediation else finding.title),
            powershell=ps, auto_fixable=curated, curated=curated, source="library",
            risk_before=finding.severity_enum.value.title(), risk_after=risk_after,
            rollback=rollback)

    # ---- Active Directory / identity (per-principal) --------------------- #
    if "pre-auth" in title or "preauth" in title or "as-rep" in title or sig == "":
        if ("pre-auth" in title or "preauth" in title or "as-rep" in title) and aff:
            return R(_loop(aff, "Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false"),
                     desc="Réactiver la pré-authentification Kerberos sur les comptes concernés.",
                     rollback="Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $true")

    if ("password never expires" in title or "n'expire" in title or "never expires" in title) and aff:
        return R(_loop(aff, "Set-ADUser -Identity $_ -PasswordNeverExpires $false"),
                 desc="Désactiver « le mot de passe n'expire jamais » sur les comptes.")

    if ("sans expiration" in title or "without expiration" in title or "account expir" in title) and aff:
        return R(_loop(aff, "Set-ADUser -Identity $_ -AccountExpirationDate (Get-Date).AddDays(90)"),
                 curated=False,
                 desc="Définir une date d'expiration (adapter la durée à votre politique).")

    if "unconstrained" in title or "non contrainte" in title:
        comps = [_strip_dollar(a) for a in aff]
        inner = "Set-ADComputer -Identity $_ -TrustedForDelegation $false"
        ps = _loop(comps, inner) if comps else \
            "Set-ADComputer -Identity <serveur_non_DC> -TrustedForDelegation $false"
        return R(ps, curated=bool(comps),
                 desc="Désactiver la délégation non contrainte sur les serveurs NON-DC concernés.",
                 rollback="Set-ADComputer -Identity <name> -TrustedForDelegation $true")

    if "inactif" in title or "stale" in title or "inactive account" in title or "dormant" in title:
        if aff:
            return R(_loop(aff, "Disable-ADAccount -Identity $_"),
                     desc="Désactiver les comptes inactifs (>90 jours).",
                     rollback="Enable-ADAccount -Identity <user>")

    # ---- Domain password / lockout policy (single command) -------------- #
    if sig == "PWD_POLICY_LENGTH" or "minimum length" in title or "minimum password" in title:
        return R("Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN -MinPasswordLength 14",
                 desc="Porter la longueur minimale du mot de passe à 14 (CIS).")
    if sig == "PWD_POLICY_MAXAGE" or ("maximum age" in title or "maximum password" in title):
        return R("Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN -MaxPasswordAge 90.00:00:00",
                 desc="Fixer un âge maximal de mot de passe (90 jours).")
    if sig == "PWD_POLICY_HISTORY" or "history length" in title:
        return R("Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN -PasswordHistoryCount 24",
                 desc="Mémoriser 24 anciens mots de passe (CIS).")
    if sig == "PWD_POLICY_COMPLEXITY" or "complexity" in title:
        return R("Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN -ComplexityEnabled $true",
                 desc="Activer la complexité des mots de passe.")
    if sig == "ACCOUNT_LOCKOUT" or "lockout" in title:
        return R("Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN "
                 "-LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00",
                 desc="Définir un verrouillage de compte (5 tentatives, 15 min).")
    if sig == "AD_MACHINE_ACCOUNT_QUOTA" or "machineaccountquota" in title.replace("-", "").replace(" ", ""):
        return R("Set-ADDomain -Identity $env:USERDNSDOMAIN "
                 "-Replace @{'ms-DS-MachineAccountQuota'='0'}",
                 desc="Mettre ms-DS-MachineAccountQuota à 0 (anti-RBCD).",
                 rollback="Set-ADDomain -Replace @{'ms-DS-MachineAccountQuota'='10'}")
    if sig == "AD_KRBTGT_STALE" or "krbtgt" in title:
        return R("# Réinitialiser le mot de passe krbtgt DEUX fois (script officiel Microsoft "
                 "New-KrbtgtKeys.ps1), en respectant le délai de réplication entre les deux.",
                 curated=False, desc="Rotation du krbtgt (procédure encadrée, hors auto-exécution).")

    # ---- Windows host (WinRM) ------------------------------------------- #
    if sig == "SMBV1_ENABLED" or "smbv1" in title:
        return R("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                 desc="Désactiver le protocole SMBv1 (obsolète et exploitable).")
    if sig == "SMB_SIGNING" or "smb signing" in title:
        return R("Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                 desc="Exiger la signature SMB (anti-relais).")
    if sig == "WIN_FIREWALL" or "firewall profile" in title:
        return R("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                 desc="Activer le pare-feu Windows sur tous les profils.")
    if sig == "WIN_SPOOLER" or "spooler" in title:
        return R("Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled",
                 desc="Arrêter et désactiver le service Spouleur d'impression (PrintNightmare).",
                 rollback="Set-Service Spooler -StartupType Automatic; Start-Service Spooler")
    if sig == "WIN_DEFENDER" or "defender" in title:
        if "tamper" in title:
            return R("# Activer la protection anti-altération via Sécurité Windows / Intune "
                     "(non modifiable de façon fiable en ligne de commande).", curated=False,
                     desc="Activer la protection anti-altération de Defender.")
        return R("Set-MpPreference -DisableRealtimeMonitoring $false",
                 desc="Réactiver la protection en temps réel de Windows Defender.")
    if sig == "GUEST_ENABLED" or ("guest account" in title):
        return R("Disable-LocalUser -Name Guest",
                 desc="Désactiver le compte invité (Guest).")
    if sig == "PSV2" or "powershell v2" in title:
        return R("Disable-WindowsOptionalFeature -Online "
                 "-FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
                 desc="Supprimer PowerShell v2 (contournement de journalisation).")
    if sig == "RDP_NLA" or "network level authentication" in title:
        return R("Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\"
                 "WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                 desc="Forcer l'authentification NLA pour RDP.")
    if sig == "CMDLINE_AUDIT" or "command-line process auditing" in title:
        return R("auditpol /set /subcategory:'Process Creation' /success:enable; "
                 "New-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\"
                 "System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 "
                 "-PropertyType DWord -Force",
                 desc="Activer l'audit des lignes de commande (événements 4688).")
    if sig == "LSA_PPL" or "protected process" in title or "runasppl" in title:
        return R("New-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                 "-Name RunAsPPL -Value 1 -PropertyType DWord -Force",
                 desc="Activer la protection LSA (RunAsPPL) contre le vol d'identifiants.",
                 rollback="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 0")

    # ---- guidance-only (shown, not auto-executable) --------------------- #
    if "kerberoast" in title or "spn" in title:
        return R("# Migrer les comptes de service vers des gMSA, ou définir un mot de passe long "
                 "(25+). Ex: Set-ADAccountPassword -Identity <svc> -Reset", curated=False,
                 desc="Renforcer les comptes de service avec SPN (gMSA recommandé).")
    if "domain admins" in title or "privileged" in title or "membres de" in title:
        remove = _loop([_strip_dollar(a) for a in aff],
                       "Remove-ADGroupMember -Identity 'Domain Admins' -Members $_ -Confirm:$false") if aff else \
                 "Remove-ADGroupMember -Identity 'Domain Admins' -Members <user> -Confirm:$false"
        return R("# ACTION DESTRUCTRICE — à valider manuellement. Retirer les comptes non "
                 "nécessaires :\n" + remove, curated=False,
                 desc="Réduire l'appartenance aux groupes privilégiés (moindre privilège).")
    # ---- SSH (Windows OpenSSH / Linux) ---------------------------------- #
    if "permitrootlogin" in title:
        return R("# Éditer C:\\ProgramData\\ssh\\sshd_config : 'PermitRootLogin no' puis "
                 "Restart-Service sshd", curated=False,
                 desc="Interdire la connexion directe en root via SSH.")
    if "passwordauthentication" in title:
        return R("# Éditer sshd_config : 'PasswordAuthentication no' (préférer les clés) puis "
                 "Restart-Service sshd", curated=False,
                 desc="Désactiver l'authentification par mot de passe SSH.")

    # ---- LDAP / NTLM signing -------------------------------------------- #
    if "ldap signing" in title or "channel binding" in title:
        return R("Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
                 "-Name LDAPServerIntegrity -Value 2",
                 desc="Exiger la signature LDAP (LDAPServerIntegrity = 2).")
    if "ntlm" in title:
        return R("# Restreindre NTLM via GPO (Network security: Restrict NTLM). "
                 "Désactiver NTLMv1 : LmCompatibilityLevel = 5.", curated=False,
                 desc="Restreindre/durcir NTLM (préférer Kerberos).")

    # ---- Windows privileges (Potato) ------------------------------------ #
    if "seimpersonate" in title or "seassignprimarytoken" in title:
        return R("# Retirer le privilège via secedit / GPO (User Rights Assignment). "
                 "Limiter SeImpersonatePrivilege aux comptes strictement nécessaires.",
                 curated=False, desc="Restreindre les privilèges d'usurpation de jeton.")

    # ---- AWS (executed via boto3, channel "aws") ------------------------- #
    if sig == "AWS_PWD_POLICY" or ("password policy" in title and "iam" in title):
        return R("aws iam update-account-password-policy --minimum-password-length 14 "
                 "--require-symbols --require-numbers --require-uppercase-characters "
                 "--require-lowercase-characters --max-password-age 90 "
                 "--password-reuse-prevention 24",
                 curated=True,
                 desc="Renforcer la politique de mots de passe IAM (>=14, complexité, rotation).")
    if sig == "AWS_KEY_AGE" or "access key" in title:
        return R("# Désactiver la clé après vérification (peut casser une application !) :\n"
                 "aws iam update-access-key --user-name <user> --access-key-id <AKIA...> "
                 "--status Inactive", curated=False,
                 desc="Désactiver puis supprimer les clés d'accès anciennes/inutilisées.")
    if sig == "AWS_ROOT_MFA" or "root account without mfa" in title:
        return R("# Action manuelle (console root requise) : activer un MFA sur l'utilisateur "
                 "root dans IAM > Security credentials.", curated=False,
                 desc="Activer le MFA sur le compte root (via la console).")
    if sig == "AWS_ROOT_KEYS" or "root account has access keys" in title:
        return R("# Action manuelle (console root) : supprimer les clés d'accès du root.",
                 curated=False, desc="Supprimer les clés d'accès du compte root.")
    if sig == "AWS_S3_PUBLIC" or "public s3" in title:
        return R("# Bloquer l'accès public (compte entier — peut casser un site statique public) :\n"
                 "aws s3control put-public-access-block --account-id <ACCOUNT_ID> "
                 "--public-access-block-configuration "
                 "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                 curated=False, desc="Activer S3 Block Public Access et retirer les ACL/policies publiques.")
    if sig == "AWS_S3_ENCRYPTION" or "without default encryption" in title:
        return R("# Par bucket : activer le chiffrement par défaut (SSE-S3) :\n"
                 "aws s3api put-bucket-encryption --bucket <BUCKET> "
                 "--server-side-encryption-configuration "
                 "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
                 curated=False, desc="Activer le chiffrement par défaut sur les buckets.")
    if sig == "AWS_SG_OPEN" or "open to the world" in title:
        return R("# Retirer la règle 0.0.0.0/0 (ADAPTER — action destructrice) :\n"
                 "aws ec2 revoke-security-group-ingress --group-id <sg-id> "
                 "--protocol tcp --port 3389 --cidr 0.0.0.0/0", curated=False,
                 desc="Restreindre l'ingress 0.0.0.0/0 aux plages d'administration.")
    if sig == "AWS_CLOUDTRAIL" or "cloudtrail" in title:
        return R("# Créer un trail multi-région (nécessite un bucket S3) :\n"
                 "aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> "
                 "--is-multi-region-trail --enable-log-file-validation ; "
                 "aws cloudtrail start-logging --name org-trail", curated=False,
                 desc="Activer un CloudTrail multi-région avec validation des logs.")
    if sig == "AWS_GUARDDUTY" or "guardduty" in title:
        return R("aws guardduty create-detector --enable", curated=False,
                 desc="Activer Amazon GuardDuty (détection de menaces). Note : coût associé.")
    if sig == "AWS_CONFIG" or "aws config" in title:
        return R("# Activer AWS Config (recorder + delivery channel) via la console ou IaC.",
                 curated=False, desc="Activer AWS Config pour l'enregistrement des changements.")
    if "mfa" in title:
        return R("# AWS CLI : imposer le MFA. Ex: aws iam create-virtual-mfa-device / "
                 "enable-mfa-device pour chaque utilisateur, et une policy de refus sans MFA.",
                 curated=False, desc="Activer le MFA pour tous les utilisateurs IAM.")
    if "administratoraccess" in title or "iam" in title:
        return R("# Remplacer AdministratorAccess par des politiques à moindre privilège "
                 "(aws iam detach-user-policy ...).", curated=False,
                 desc="Réduire les privilèges IAM (moindre privilège).")

    if sig.startswith("NET_") or "exposed" in title or "reachable" in title:
        svc = finding.title.split(" exposed")[0]
        return R("# Restreindre l'exposition via le pare-feu (adapter aux réseaux d'administration) :\n"
                 f"New-NetFirewallRule -DisplayName 'Restrict {svc}' -Direction Inbound "
                 "-RemoteAddress <plage_admin> -Action Allow", curated=False,
                 desc="Limiter le service aux réseaux d'administration / VPN.")

    return None
