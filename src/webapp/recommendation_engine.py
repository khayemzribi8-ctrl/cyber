# src/webapp/recommendation_engine.py
import os
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime

# google-generativeai is optional and imported lazily (only when the AI features
# are actually used), so the platform runs fully offline without it.
try:
    from src.utils.aws_sns import send_sns_alert
except Exception:  # boto3 / aws optional
    def send_sns_alert(*a, **k):
        return False


def _genai():
    import google.generativeai as genai  # lazy: only when AI is used
    return genai

# cache the working model name so we don't re-resolve on every call
_RESOLVED_MODEL = None
# candidate models tried in order; Google renames these over time, so the list
# is only a fallback — the resolver first asks the API what is actually available.
_MODEL_CANDIDATES = [
    "gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.0-flash",
    "gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-pro",
]


def _resolve_model_name() -> str:
    """Pick a usable Gemini model: env override, else ask the API, else fallback."""
    global _RESOLVED_MODEL
    if _RESOLVED_MODEL:
        return _RESOLVED_MODEL
    env = os.environ.get("GEMINI_MODEL")
    if env:
        _RESOLVED_MODEL = env
        return env
    # ask the API which models support text generation, prefer a "flash" one
    try:
        available = []
        for m in _genai().list_models():
            methods = getattr(m, "supported_generation_methods", []) or []
            if "generateContent" in methods:
                available.append(m.name.split("/")[-1])
        for pref in _MODEL_CANDIDATES:
            if pref in available:
                _RESOLVED_MODEL = pref
                return pref
        flash = [a for a in available if "flash" in a]
        if flash:
            _RESOLVED_MODEL = flash[0]
            return flash[0]
        if available:
            _RESOLVED_MODEL = available[0]
            return available[0]
    except Exception:
        pass
    _RESOLVED_MODEL = _MODEL_CANDIDATES[0]
    return _RESOLVED_MODEL


def _generate(prompt: str) -> str:
    """Generate text, trying candidate models if one is unavailable (404)."""
    global _RESOLVED_MODEL
    tried = []
    names = [_resolve_model_name()] + [m for m in _MODEL_CANDIDATES if m != _RESOLVED_MODEL]
    last_err = None
    for name in names:
        if name in tried:
            continue
        tried.append(name)
        try:
            resp = _genai().GenerativeModel(name).generate_content(prompt)
            _RESOLVED_MODEL = name  # remember the one that worked
            return resp.text.strip()
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            # only fall through on "model not found / unavailable" style errors
            if "not found" in msg or "404" in msg or "no longer available" in msg or "unsupported" in msg:
                _RESOLVED_MODEL = None
                continue
            raise
    raise last_err or RuntimeError("No usable Gemini model")


# --------------------------------------------------------------------------- #
# Local LLM backend: Ollama (default). No API key, fully offline/private.
# Uses only the standard library so there is no extra dependency.
# --------------------------------------------------------------------------- #
import json as _json
import re as _re
import urllib.request as _urlreq
import urllib.error as _urlerr


def _ollama_url() -> str:
    return os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")


def _ollama_model() -> str:
    # Small, fast coder model — plenty for generating a single hardening command.
    # Override with OLLAMA_MODEL to match your `ollama list` (e.g. qwen2.5-coder:3b,
    # qwen2.5-coder:1.5b for smaller machines, or qwen3-coder:30b if you have the RAM).
    return os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")


def _strip_think(text: str) -> str:
    # some Qwen models emit <think>...</think> reasoning; keep only the answer
    return _re.sub(r"<think>.*?</think>", "", text, flags=_re.DOTALL).strip()


def _ollama_generate(prompt: str, timeout: int = 180) -> str:
    """Call a local Ollama server's /api/generate endpoint (non-streaming)."""
    body = _json.dumps({
        "model": _ollama_model(),
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 512},
    }).encode("utf-8")
    req = _urlreq.Request(_ollama_url() + "/api/generate", data=body,
                          headers={"Content-Type": "application/json"})
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        return _strip_think(data.get("response", "").strip())
    except _urlerr.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")[:200]
        except Exception:
            pass
        if e.code == 404:
            raise RuntimeError(
                f"Ollama: modèle '{_ollama_model()}' introuvable. Faites "
                f"`ollama pull {_ollama_model()}` (ou ajustez OLLAMA_MODEL). {detail}")
        raise RuntimeError(f"Ollama HTTP {e.code}: {detail}")
    except _urlerr.URLError as e:
        raise RuntimeError(
            f"Ollama injoignable sur {_ollama_url()} — lancez `ollama serve`. ({e.reason})")


def ai_provider() -> str:
    """Which AI backend to use: 'ollama' (default, local) or 'gemini'."""
    return os.environ.get("AI_PROVIDER", "ollama").strip().lower()


def _ai_complete(prompt: str) -> str:
    """Dispatch a completion to the configured AI backend."""
    if ai_provider() == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY manquant (AI_PROVIDER=gemini).")
        _genai().configure(api_key=api_key)
        return _generate(prompt)
    return _ollama_generate(prompt)


# Commandes PowerShell prédéfinies pour les correctifs courants
PS_COMMANDS = {
    "disable_password_never_expires": (
        "Set-ADUser -Identity '{user}' -PasswordNeverExpires $false"
    ),
    "set_account_expiration": (
        "Set-ADUser -Identity '{user}' -AccountExpirationDate ((Get-Date).AddDays(90))"
    ),
    "enable_kerberos_preauth": (
        "Set-ADAccountControl -Identity 'User_NoKrb' -DoesNotRequirePreAuth $false"
    ),
    "disable_inactive_account": (
        "Disable-ADAccount -Identity '{user}'"
    ),
    "remove_seimpersonate": r"""
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace 'SeImpersonatePrivilege = .*', 'SeImpersonatePrivilege =' | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\new.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS
Remove-Item C:\secpol.cfg -Force
""",
    "remove_seassignprimary": r"""
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace 'SeAssignPrimaryTokenPrivilege = .*', 'SeAssignPrimaryTokenPrivilege =' | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\new.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS
Remove-Item C:\secpol.cfg -Force
""",
    "disable_printspooler": r"""
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
"""
}

# fonction pour preparer une commande powershell
def wrap_ps(command: str) -> str:
    """
    Prépare une commande PowerShell pour exécution distante sécurisée via WinRM/SSH.
    Échappe les $, supprime CRLF, force l'import du module AD.
    """
    cmd = command.strip().replace("\r", "").replace("\n", "; ")
    cmd = cmd.replace("$", "`$")  # Échappement pour SSH
    return (
        'powershell -NoLogo -NoProfile -ExecutionPolicy Bypass '
        f'-Command "Import-Module ActiveDirectory -ErrorAction SilentlyContinue; {cmd}"'
    )

# fonction pour generer des conseils de securite via Gemini
def ai_generate_security_advice(ssh_script: str, ldap_script: str) -> str:
    """
    Génère des conseils de durcissement Windows via le backend IA configuré
    (Ollama en local par défaut, ou Gemini).
    """
    if not ssh_script.strip() and not ldap_script.strip():
        return "Aucun script de correction généré → pas de recommandation IA supplémentaire."

    try:
        prompt = f"""
Tu es un expert Blue Team spécialisé en sécurité Windows Server et Active Directory.

Analyse les scripts de correction suivants et propose des recommandations complémentaires pertinentes.

Scripts fournis :
=== Correctifs SSH (OpenSSH Windows) ===
{ssh_script or "Aucun"}

=== Correctifs Active Directory ===
{ldap_script or "Aucun"}

Réponds UNIQUEMENT au format suivant, sans introduction ni conclusion :

## 🔐 OpenSSH Windows
- Problème potentiel :
- Recommandation PowerShell :
- Justification :

## 🏢 Active Directory
- Problème potentiel :
- Recommandation PowerShell :
- Justification :

## 🛡️ Durcissement général Windows
- Bonne pratique :
- Commande PowerShell applicable :
- Bénéfice sécurité :

Règles strictes :
- UNIQUEMENT des commandes PowerShell valides et exécutables
- Pas de Linux, Bash, sshd_config Linux, sudo, apt, etc.
- Pas de théorie longue
- Priorité aux actions concrètes et immédiates
"""

        return _ai_complete(prompt)

    except Exception as e:
        return f"❌ Erreur lors de la génération IA : {str(e)}"


def ai_suggest_command(title: str, description: str = "", affected=None,
                       platform: str = "windows") -> dict:
    """Ask the configured local/remote LLM for a single hardening command.

    ``platform`` selects the expected command flavour: "aws" -> AWS CLI,
    "linux" -> shell, anything else -> PowerShell (Windows/AD).
    Backend is Ollama by default (AI_PROVIDER=ollama, e.g. Qwen3-Coder), or
    Gemini (AI_PROVIDER=gemini). The result is ALWAYS a suggestion to review —
    it is never auto-executed.
    """
    provider = ai_provider()
    backend = f"Ollama ({_ollama_model()})" if provider == "ollama" else "Gemini"
    if platform == "aws":
        role = "un expert sécurité AWS / IAM"
        lang = "AWS CLI (commande `aws ...`)"
    elif platform == "linux":
        role = "un expert sécurité Linux"
        lang = "shell Linux"
    else:
        role = "un expert Blue Team Windows/Active Directory"
        lang = "PowerShell"
    try:
        aff = ", ".join(affected) if affected else ""
        prompt = f"""Tu es {role}.
Pour la vulnérabilité suivante, propose UNE seule commande de durcissement, idempotente,
non destructrice, exécutable à distance.

Vulnérabilité : {title}
Détails : {description}
Éléments affectés : {aff or "n/a"}

Réponds STRICTEMENT au format :
COMMANDE: <une seule commande {lang}, sur une ligne>
EXPLICATION: <une phrase>
Règles : {lang} valide uniquement ; pas de suppression de comptes/objets ; pas de texte hors format."""
        text = _ai_complete(prompt)
        cmd, expl = "", ""
        for line in text.splitlines():
            if line.upper().startswith("COMMANDE:"):
                cmd = line.split(":", 1)[1].strip().strip("`")
            elif line.upper().startswith("EXPLICATION:"):
                expl = line.split(":", 1)[1].strip()
        if not cmd:
            # model didn't follow the format — take the first code-looking line
            for line in text.splitlines():
                if line.strip() and not line.strip().startswith(("#", "```")):
                    cmd = line.strip().strip("`")
                    break
            cmd = cmd or text.strip()
        return {"ok": True, "ai": True, "command": cmd, "explanation": expl,
                "backend": backend,
                "message": f"Suggestion {backend} — à vérifier avant toute exécution "
                           "(non exécutée automatiquement)."}
    except Exception as e:
        return {"ok": False, "ai": True, "backend": backend,
                "message": f"Erreur IA ({backend}) : {e}"}

# fonction pour construire des recommandations a partir des resultats
def build_recommendations(results: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Génère la liste des recommandations automatisées avec correctifs exécutables.
    """
    recommendations = []

    for module, items in results.items():
        for item in items:
            check = item.get("check", "")
            result = item.get("result", "")
            severity = item.get("severity", "INFO")

            if severity == "OK":
                continue

            # Normalisation des éléments affectés
            affected = []
            if isinstance(result, str):
                affected = [x.strip() for x in result.split(",") if x.strip()]
            elif isinstance(result, list):
                affected = result

            service = module

            # mot de passe n'expire jamais
            if "Password Never Expires" in check:
                for user in affected:
                    recommendations.append({
                        "name": f"Mot de passe n'expire jamais : {user}",
                        "severity": "WARN",
                        "service": service,
                        "affected": [user],
                        "command_template": wrap_ps(PS_COMMANDS["disable_password_never_expires"].format(user=user))
                    })
                continue

            # compte sans date d'expiration
            if "sans date d'expiration" in check.lower():
                for user in affected:
                    recommendations.append({
                        "name": f"Compte sans expiration : {user}",
                        "severity": "WARN",
                        "service": service,
                        "affected": [user],
                        "command_template": wrap_ps(PS_COMMANDS["set_account_expiration"].format(user=user))
                    })
                continue

            # pré-authentification Kerberos désactivée
            if "Pre-Auth" in check or "Do not require Kerberos preauthentication" in check:
                for user in affected:
                    recommendations.append({
                        "name": f"Pré-authentification Kerberos désactivée : {user}",
                        "severity": "CRIT",
                        "service": service,
                        "affected": [user],
                        "command_template": wrap_ps(PS_COMMANDS["enable_kerberos_preauth"].format(user=user))
                    })
                continue

            # compte inactif
            if "inactif" in check.lower() or "stale" in check.lower():
                for user in affected:
                    recommendations.append({
                        "name": f"Compte inactif (>90 jours) : {user}",
                        "severity": "WARN",
                        "service": service,
                        "affected": [user],
                        "command_template": wrap_ps(PS_COMMANDS["disable_inactive_account"].format(user=user))
                    })
                continue

            # services et privileges dangereux
            if "SeImpersonatePrivilege" in check:
                recommendations.append({
                    "name": "Privilège SeImpersonatePrivilege activé (risque Potato)",
                    "severity": "CRIT",
                    "service": service,
                    "affected": ["Système local"],
                    "command_template": wrap_ps(PS_COMMANDS["remove_seimpersonate"])
                })
                continue

            if "SeAssignPrimaryTokenPrivilege" in check:
                recommendations.append({
                    "name": "Privilège SeAssignPrimaryTokenPrivilege activé (risque Potato)",
                    "severity": "WARN",
                    "service": service,
                    "affected": ["Système local"],
                    "command_template": wrap_ps(PS_COMMANDS["remove_seassignprimary"])
                })
                continue

            # spooler d'impression
            if "Spooler" in check or "PrintNightmare" in check:
                recommendations.append({
                    "name": "Service Print Spooler activé (risque PrintNightmare)",
                    "severity": "WARN",
                    "service": service,
                    "affected": ["Print Spooler"],
                    "command_template": wrap_ps(PS_COMMANDS["disable_printspooler"])
                })
                continue

            # ACL critiques sur Domain Admins
            if "acl" in check.lower() and "Domain Admins" in result:
                recommendations.append({
                    "name": "ACL incorrectes sur objet critique (Domain Admins)",
                    "severity": "CRIT",
                    "service": service,
                    "affected": ["Domain Admins"],
                    "command_template": None  # Trop risqué à automatiser
                })
                continue

            # Recommandation générique si aucun correctif spécifique n'est défini
            recommendations.append({
                "name": check or "Vulnérabilité détectée",
                "severity": severity,
                "service": service,
                "affected": affected,
                "command_template": None
            })

            # Envoi d'alerte SNS pour les vulnérabilités critiques et importantes
            if severity in ("CRIT", "WARN") and module in {"Active Directory", "Privilege", "Token", "Potato", "ACL"}:
                send_sns_alert(
                    subject=f"[CyberAudit] Alerte {severity} - {check}",
                    message=f"""
                        🔴 Nouvelle vulnérabilité détectée

                        📌 Module     : {module}
                        ⚠️  Sévérité   : {severity}
                        🔍 Problème    : {check}
                        🎯 Affecte     : {', '.join(affected) if affected else 'Système global'}

                        ⏰ Date        : {datetime.now().strftime("%d %B %Y à %H:%M")}
                        🔗 Dashboard  : os.environ.get("DEFAULT_URL", "http://your-dashboard-url/recommendations")

                        Action recommandée immédiate.
                                            """.strip()
                )

    return recommendations
