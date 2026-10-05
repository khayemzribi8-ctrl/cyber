from typing import List, Dict, Any

# Génération de scripts de remédiation PowerShell pour les problèmes SSH et LDAP/AD
def generate_ssh_fixes(findings_ssh: List[Dict[str, Any]]) -> str:
    """
    Génère un script PowerShell de remédiation pour les problèmes SSH détectés
    sur un serveur Windows avec OpenSSH installé.
    """
    if not findings_ssh:
        return "# Aucun résultat SSH à analyser."

    fixes = []
    config_path = r"C:\ProgramData\ssh\sshd_config"
    service_name = "sshd"

    # 1. Désactiver PermitRootLogin
    if any(
        f.get("check") == "PermitRootLogin" and f.get(
            "severity") in ("CRIT", "WARN")
        for f in findings_ssh
    ):
        fixes.append(
            f"""# Désactiver la connexion directe en root (recommandé pour la sécurité)
$configPath = "{config_path}"
if (Test-Path $configPath) {{
    $content = Get-Content $configPath -Raw
    if ($content -match "^\\s*PermitRootLogin") {{
        (Get-Content $configPath) -replace "^\\s*PermitRootLogin\\s+.*$", "PermitRootLogin no" | Set-Content $configPath
    }} else {{
        Add-Content $configPath -Value "PermitRootLogin no"
    }}
    Write-Host "PermitRootLogin configuré sur 'no'"
}} else {{
    Write-Warning "Fichier sshd_config non trouvé : $configPath"
}}
Restart-Service {service_name} -Force
"""
        )

    # 2. Désactiver PasswordAuthentication (préférer les clés)
    if any(
        f.get("check") == "PasswordAuthentication" and f.get(
            "severity") in ("WARN", "CRIT")
        for f in findings_ssh
    ):
        fixes.append(
            f"""# Désactiver l'authentification par mot de passe (forcer l'usage de clés SSH)
$configPath = "{config_path}"
if (Test-Path $configPath) {{
    $content = Get-Content $configPath -Raw
    if ($content -match "^\\s*PasswordAuthentication") {{
        (Get-Content $configPath) -replace "^\\s*PasswordAuthentication\\s+.*$", "PasswordAuthentication no" | Set-Content $configPath
    }} else {{
        Add-Content $configPath -Value "PasswordAuthentication no"
    }}
    Write-Host "PasswordAuthentication désactivé"
}} else {{
    Write-Warning "Fichier sshd_config non trouvé : $configPath"
}}
Restart-Service {service_name} -Force
"""
        )

    # 3. Ajouter une bannière légale d'avertissement
    if any(
        "banner" in str(f.get("check", "")).lower() or
        "Not configured" in str(f.get("result", "")) and "banner" in str(
            f.get("check", "")).lower()
        for f in findings_ssh
    ):
        banner_path = r"C:\ProgramData\ssh\banner.txt"
        fixes.append(
            f"""# Ajouter une bannière d'avertissement légale avant connexion
$bannerPath = "{banner_path}"
$bannerContent = @"
********************************************************************
*                ACCÈS RÉSERVÉ AUX UTILISATEURS AUTORISÉS          *
*                                                                  *
* Toute connexion non autorisée sera tracée et pourra faire        *
* l'objet de poursuites judiciaires.                               *
********************************************************************
"@

if (-not (Test-Path $bannerPath)) {{
    $bannerContent | Out-File -FilePath $bannerPath -Encoding UTF8
    Write-Host "Bannière créée : $bannerPath"
}}

$configPath = "{config_path}"
if (Test-Path $configPath) {{
    $hasBanner = Select-String -Path $configPath -Pattern "^Banner" -Quiet
    if (-not $hasBanner) {{
        Add-Content $configPath -Value "Banner {banner_path.replace(chr(92), "/")}"
        Write-Host "Ligne Banner ajoutée au sshd_config"
    }}
    Restart-Service {service_name} -Force
}} else {{
    Write-Warning "Fichier sshd_config non trouvé : $configPath"
}}
"""
        )
    # 4. Restreindre autres options de sécurité si nécessaire (exemples)
    if not fixes:
        return "# Aucun problème SSH nécessitant une correction automatique détecté.\n# Votre configuration semble déjà sécurisée sur les points vérifiés."

    return "# === SCRIPT DE DURCISSEMENT SSH (Windows OpenSSH) ===\n" + "\n\n".join(fixes)

# Génération de scripts de remédiation PowerShell pour les problèmes LDAP/AD
def generate_ldap_ad_fixes(
    findings_ldap: List[Dict[str, Any]],
    findings_ad: List[Dict[str, Any]]
) -> str:
    """
    Génère un script PowerShell de remédiation pour les problèmes LDAP/AD courants.
    Priorité à la sécurité et à l'idempotence.
    """
    all_findings = findings_ldap + findings_ad
    if not all_findings:
        return "# Aucun résultat LDAP/Active Directory à analyser."

    fixes = []

    # 1. Comptes avec mot de passe qui n'expire jamais
    if any(
        "Password Never Expires" in str(f.get("check", "")) and f.get(
            "severity") in ("CRIT", "WARN")
        for f in all_findings
    ):
        fixes.append(
            """# Désactiver l'option "Le mot de passe n'expire jamais" sur les comptes à risque
Import-Module ActiveDirectory

# Exemple : ciblage des comptes critiques détectés (à adapter selon vos besoins)
# Vous pouvez lister manuellement ou automatiser via une recherche
$riskyUsers = @("admin", "service_sql", "backup")  # ← À REMPLIR avec les comptes détectés

foreach ($user in $riskyUsers) {
    try {
        $adUser = Get-ADUser -Identity $user -Properties PasswordNeverExpires
        if ($adUser.PasswordNeverExpires) {
            Set-ADUser -Identity $user -PasswordNeverExpires $false
            Write-Host "Mot de passe forcé à expirer pour : $user"
        }
    } catch {
        Write-Warning "Impossible de traiter l'utilisateur : $user - $_"
    }
}

# Option alternative : tous les comptes humains (hors services)
# Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
#   Where-Object { $_.Name -notlike "*svc*" -and $_.Name -notlike "*service*" } |
#   Set-ADUser -PasswordNeverExpires $false
"""
        )

    # 2. Protection contre Kerberoasting (comptes avec SPN + mot de passe faible/ancien)
    if any(
        "Kerberoast" in str(f.get("check", "")) or "SPN" in str(
            f.get("check", ""))
        for f in all_findings
    ):
        fixes.append(
            """# Renforcer les comptes Kerberoastables (avec SPN défini)
Import-Module ActiveDirectory

# Liste des comptes de service détectés avec SPN (à adapter)
$spnAccounts = @("SQLService", "WebService", "BackupSvc")  # ← À REMPLIR

foreach ($account in $spnAccounts) {
    try {
        # Forcer un mot de passe fort (génération aléatoire de 32 caractères)
        $newPassword = -join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        $securePass = ConvertTo-SecureString $newPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $account -NewPassword $securePass -Reset
        Set-ADUser -Identity $account -PasswordNeverExpires $false

        Write-Host "Mot de passe renforcé pour le compte : $account"
        Write-Host "Nouveau mot de passe (à stocker en lieu sûr) : $newPassword"
    } catch {
        Write-Warning "Échec sur $account : $_"
    }
}
"""
        )

    # 3. Délégation non contrainte (Unconstrained Delegation) - CRITIQUE
    if any(
        "unconstrained delegation" in str(f.get("result", "")).lower() or
        "Trusted for delegation" in str(f.get("check", ""))
        for f in all_findings
    ):
        fixes.append(
            """# Désactiver la délégation non contrainte (très risquée)
Import-Module ActiveDirectory

# Liste des machines ou comptes avec délégation non contrainte (à adapter)
$delegatedComputers = @("WIN-M594PNTC1Q5$")  # ← À REMPLIR avec les noms détectés

foreach ($comp in $delegatedComputers) {
    try {
        Set-ADComputer -Identity $comp -TrustedForDelegation $false
        Write-Host "Délégation non contrainte désactivée sur : $comp"
    } catch {
        Write-Warning "Échec sur $comp : $_"
    }
}
"""
        )

    if not fixes:
        return "# Aucune vulnérabilité LDAP/Active Directory nécessitant une correction automatique détectée.\n# Votre domaine semble déjà bien sécurisé sur les points vérifiés."

    return "# === SCRIPT DE DURCISSEMENT ACTIVE DIRECTORY ===\n" + "\n\n".join(fixes)
