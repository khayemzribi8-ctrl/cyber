import json
import os
from typing import Dict, List, Any, Optional, Tuple
import paramiko
import time
import csv
from io import StringIO
from flask import render_template, request, redirect, url_for, jsonify, make_response
from . import app
from .winrm_exec import run_ps
from src.utils.dynamodb import save_audit
from src.utils.cloudwatch import publish_audit_metrics
from src.auditors import (
    audit_ldap, audit_ssh, audit_ad,
    audit_privilege, audit_token, audit_acl, audit_potato, audit_aws
)
from src.utils.config import load_env, str2bool
from .protection import generate_ssh_fixes, generate_ldap_ad_fixes
from .recommendation_engine import (
    build_recommendations,
    ai_generate_security_advice
)
from src.utils.aws_sns import send_sns_alert

# initialisation des variables globales
LAST_RESULTS: Dict[str, List[Dict[str, Any]]] = {}
RECOMMENDATIONS_CACHE: List[Dict[str, Any]] = []
OUTPUTS_DIR = os.path.join(os.path.dirname(
    os.path.dirname(os.path.dirname(__file__))), "outputs")
os.makedirs(OUTPUTS_DIR, exist_ok=True)

# mappage des noms de modules pour l'affichage
MODULE_DISPLAY_TO_KEY = {
    "Active Directory": "Active Directory",
    "ad": "Active Directory",
    "activedirectory": "Active Directory",
    "Privilege": "Privilege",
    "privesc": "Privilege",
    "Token": "Token",
    "kerberos": "Token",
    "ACL": "ACL",
    "Potato": "Potato",
    "AWS": "AWS",
    "LDAP": "LDAP",
    "SSH": "SSH"
}

# mappage des clés DynamoDB aux noms d'affichage
DYNAMODB_KEY_TO_DISPLAY = {
    "ldap": "LDAP",
    "ssh": "SSH",
    "ad": "Active Directory",
    "privesc": "Privilege",
    "token": "Token",
    "acl": "ACL",
    "potato": "Potato",
    "aws": "AWS"
}

# Configuration par défaut
DEFAULT_CONFIG = {
    "LDAP": {"host": "127.0.0.1", "port": 389, "ssl": False, "base_dn": None},
    "SSH": {"port": 22, "key_path": ""},
    "AD": {"port": 389}
}

# ========================
# fonctions utilitaires
# ========================

# Sauvegarde et chargement des derniers résultats


def save_last_results():
    path = os.path.join(OUTPUTS_DIR, "last_results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(LAST_RESULTS, f, indent=2)

# Chargement des derniers résultats


def load_last_results():
    global LAST_RESULTS
    path = os.path.join(OUTPUTS_DIR, "last_results.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                LAST_RESULTS = json.load(f)
        except json.JSONDecodeError:
            LAST_RESULTS = {}
            app.logger.error("Failed to load last_results.json")

# Calcul du résumé des résultats


def compute_summary(items: List[Dict] | Dict) -> Dict[str, int]:
    summary = {"OK": 0, "WARN": 0, "CRIT": 0, "INFO": 0}
    if isinstance(items, dict):
        iterator = items.values()
    else:
        iterator = [items]

    for module_results in iterator:
        if not isinstance(module_results, list):
            continue
        for item in module_results:
            if isinstance(item, dict):
                sev = item.get("severity", "INFO")
                summary[sev] += 1
    return summary

# Validation de la configuration d'environnement


def validate_env_config() -> Dict[str, Any]:
    config = {
        "LDAP": {
            "host": os.environ.get("LDAP_HOST", DEFAULT_CONFIG["LDAP"]["host"]),
            "port": int(os.environ.get("LDAP_PORT", DEFAULT_CONFIG["LDAP"]["port"])),
            "ssl": str2bool(os.environ.get("LDAP_SSL", "false")),
            "bind_dn": os.environ.get("LDAP_BIND_DN", ""),
            "password": os.environ.get("LDAP_PASSWORD", ""),
            "base_dn": os.environ.get("LDAP_BASE_DN", None)
        },
        "SSH": {
            "host": os.environ.get("SSH_HOST", os.environ.get("LDAP_HOST", "127.0.0.1")),
            "port": int(os.environ.get("SSH_PORT", DEFAULT_CONFIG["SSH"]["port"])),
            "username": os.environ.get("SSH_USERNAME", ""),
            "password": os.environ.get("SSH_PASSWORD", ""),
            "key_path": os.environ.get("SSH_KEY_PATH", DEFAULT_CONFIG["SSH"]["key_path"])
        },
        "AD": {
            "host": os.environ.get("AD_HOST", ""),
            "port": int(os.environ.get("AD_PORT", DEFAULT_CONFIG["AD"]["port"])),
            "domain": os.environ.get("AD_DOMAIN", ""),
            "bind_dn": os.environ.get("AD_BIND_DN", ""),
            "password": os.environ.get("AD_PASSWORD", "")
        }
    }
    return config

# Gestion des erreurs lors de l'exécution des audits


def run_audit_with_error_handling(audit_func, func_name: str, **kwargs):
    try:
        return audit_func(**kwargs)
    except Exception as e:
        app.logger.error(f"{func_name} audit failed: {str(e)}")
        return [{
            "check": f"{func_name} audit error",
            "result": str(e),
            "severity": "CRIT",
            "recommendation": f"Vérifier la configuration et la connectivité pour {func_name}."
        }]

# Normalisation des données d'audit DynamoDB ( pour l'affichage cohérent )


def normalize_audit_data(audit_item: Dict) -> Dict:
    """Normalize raw DynamoDB audit data for consistent use."""
    normalized = {}

    def fix_item(item):
        if isinstance(item, dict):
            return item
        return {"check": "Unknown", "result": str(item), "severity": "INFO"}

    for db_key, display_key in DYNAMODB_KEY_TO_DISPLAY.items():
        value = audit_item.get(db_key)
        if value is None:
            normalized[display_key] = []
        elif isinstance(value, str):
            normalized[display_key] = [fix_item(value)]
        elif isinstance(value, list):
            normalized[display_key] = [fix_item(v) for v in value]
        else:
            normalized[display_key] = []

    # combiner toutes les données
    normalized["all_data"] = {
        display_key: normalized.get(display_key, [])
        for display_key in MODULE_DISPLAY_TO_KEY.values()
    }
    normalized["all_data"] = {k: v for k,
                              v in normalized["all_data"].items() if v}

    # copier les autres champs pertinents
    for key in ["audit_id", "timestamp", "summary", "modules_used"]:
        if key in audit_item:
            normalized[key] = audit_item[key]

    return normalized

# Accès à la table DynamoDB


def get_dynamodb_table():
    import boto3
    return boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION")).Table(os.getenv("DYNAMODB_TABLE"))

# ========================
# App Initialization
# ========================

# Initialisation de l'application avant la première requête


@app.before_request
def init_app():
    if not hasattr(app, "_initialized"):
        load_env()
        load_last_results()
        app._initialized = True

# ========================
# Routes
# ========================

# Récupération du score de sécurité actuel depuis CloudWatch
def get_current_score():
    import boto3
    from datetime import datetime, timedelta
    try:
        client = boto3.client(
            'cloudwatch', region_name=os.environ.get("AWS_REGION"))

        response = client.get_metric_statistics(
            Namespace='CyberAuditTool',
            MetricName='SecurityScore',
            Dimensions=[{'Name': 'Project', 'Value': 'CyberAudit'}],
            StartTime=datetime.utcnow() - timedelta(days=30),  # Very wide window
            EndTime=datetime.utcnow(),
            Period=86400,
            Statistics=['Maximum', 'SampleCount']
        )

        datapoints = sorted(response['Datapoints'],
                            key=lambda x: x['Timestamp'], reverse=True)

        if datapoints:
            latest = datapoints[0]['Maximum']
            print(f"Latest SecurityScore from CloudWatch: {latest}")
            return latest

        print("No SecurityScore datapoints found in CloudWatch")
        return None

    except Exception as e:
        print(f"CloudWatch fetch failed: {e}")
        return None

# Route du tableau de bord principal
# Afficher le tableau de bord principal avec les résultats d'audit
@app.route("/")
def dashboard():
    global RECOMMENDATIONS_CACHE
    summary = compute_summary(LAST_RESULTS) if LAST_RESULTS else None
    if LAST_RESULTS:
        RECOMMENDATIONS_CACHE = build_recommendations(LAST_RESULTS)

    current_score = get_current_score()
    return render_template(
        "dashboard.html",
        results=LAST_RESULTS,
        summary=summary,
        modules=list(LAST_RESULTS.keys()),
        current_score=get_current_score()
    )


# Route de lancement d'audit
# Lancer un audit basé sur le formulaire soumis
@app.route("/run-audit", methods=["POST"])
def run_audit():
    global LAST_RESULTS
    config = validate_env_config()
    results: Dict[str, List[Dict]] = {}

    audit_mappings = {
        "do_ldap": ("LDAP", audit_ldap.run, config["LDAP"]),
        "do_ssh": ("SSH", audit_ssh.run, config["SSH"]),
        "do_ad": ("Active Directory", audit_ad.run, config["AD"]),
        "do_privilege": ("Privilege", audit_privilege.run, config["AD"]),
        "do_token": ("Token", audit_token.run, config["AD"]),
        "do_acl": ("ACL", audit_acl.run, config["SSH"]),
        "do_potato": ("Potato", audit_potato.run, config["SSH"]),
        "do_aws": ("AWS", audit_aws.run, {}),
    }

    for form_key, (key, func, args) in audit_mappings.items():
        if request.form.get(form_key):
            results[key] = run_audit_with_error_handling(func, key, **args)

    LAST_RESULTS = results
    save_last_results()

    summary = compute_summary(results)

    publish_audit_metrics(summary)
    # Sauvegarde de l'audit dans DynamoDB
    try:
        save_audit(
            ldap=results.get("LDAP"),
            ssh=results.get("SSH"),
            ad=results.get("Active Directory"),
            privilege=results.get("Privilege"),
            token=results.get("Token"),
            acl=results.get("ACL"),
            potato=results.get("Potato"),
            aws_iam=results.get("AWS"),
            summary=summary,
            modules_used=list(results.keys()),
        )
    except Exception as e:
        app.logger.error(f"Failed to save audit to DynamoDB: {str(e)}")

    return redirect(url_for("dashboard"))

# Route des détails par module
# Afficher les détails des résultats pour un module spécifique
@app.route("/details/<module_name>")
def details(module_name: str):
    module_key = MODULE_DISPLAY_TO_KEY.get(module_name.lower(), module_name)
    items = LAST_RESULTS.get(module_key, [])
    return render_template("details.html", module_name=module_key, items=items, item_count=len(items))

# Route de la vue de protection
# Afficher les scripts de correctifs pour LDAP, AD et SSH
@app.route("/protection")
def protection_view():
    ldap_items = LAST_RESULTS.get("LDAP", [])
    ad_items = LAST_RESULTS.get("Active Directory", [])
    ssh_items = LAST_RESULTS.get("SSH", [])

    ssh_script = generate_ssh_fixes(
        ssh_items) if ssh_items else "# No SSH issues found"
    ldap_ad_script = generate_ldap_ad_fixes(
        ldap_items, ad_items) if ldap_items or ad_items else "# No LDAP/AD issues found"

    return render_template(
        "protection.html",
        ssh_script=ssh_script,
        ldap_ad_script=ldap_ad_script,
        has_ssh_issues=bool(ssh_items),
        has_ldap_issues=bool(ldap_items or ad_items)
    )

# Route de la vue des recommandations
# Afficher les recommandations de sécurité basées sur les résultats d'audit
@app.route("/recommendations")
def recommendations_view():
    global RECOMMENDATIONS_CACHE
    if not LAST_RESULTS:
        return render_template("recommendations.html", recommendations=[], summary=None, total=0)

    RECOMMENDATIONS_CACHE = build_recommendations(LAST_RESULTS)
    summary = compute_summary(RECOMMENDATIONS_CACHE)

    return render_template(
        "recommendations.html",
        recommendations=RECOMMENDATIONS_CACHE,
        summary=summary,
        total=len(RECOMMENDATIONS_CACHE)
    )

# Route de génération AI
# Générer des conseils de sécurité via AI
@app.route("/ai-generate", methods=["POST"])
def ai_generate():
    data = request.get_json() or {}
    ssh_script = data.get("ssh", "")
    ldap_script = data.get("ldap", "")

    if not ssh_script and not ldap_script:
        return jsonify({"error": "No scripts provided"}), 400

    # Appel de la fonction AI pour générer des conseils
    try:
        text = ai_generate_security_advice(ssh_script, ldap_script)
        return jsonify({"text": text})
    except Exception as e:
        app.logger.error(f"AI generation failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ========================
# Fix Execution Helpers
# ========================

# Exécution des correctifs SSH en batch
def execute_ssh_batch(fixes: List[Tuple[int, Dict, str]]) -> List[Dict]:
    results = []
    config = validate_env_config()["SSH"]

    if not config["username"] or (not config["password"] and not os.path.exists(config["key_path"])):
        msg = "Configuration SSH manquante"
        return [{"id": fid, "title": rec.get("name", "Unknown"), "success": False, "message": msg} for fid, rec, _ in fixes]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if config["key_path"] and os.path.exists(config["key_path"]):
            key = paramiko.RSAKey.from_private_key_file(config["key_path"])
            ssh.connect(config["host"], port=config["port"],
                        username=config["username"], pkey=key)
        else:
            ssh.connect(config["host"], port=config["port"],
                        username=config["username"], password=config["password"])

        for fix_id, rec, command in fixes:
            try:
                stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
                start = time.time()
                output, error = "", ""
                while time.time() - start < 30:
                    if stdout.channel.recv_ready():
                        output += stdout.read().decode(errors="ignore")
                        error += stderr.read().decode(errors="ignore")
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Command timed out")

                results.append({
                    "id": fix_id,
                    "title": rec.get("name", "Unknown"),
                    "success": not error.strip(),
                    "message": (output or error or "Exécuté avec succès").strip()[:500]
                })
            except Exception as e:
                results.append({
                    "id": fix_id,
                    "title": rec.get("name", "Unknown"),
                    "success": False,
                    "message": f"Erreur SSH: {str(e)}"
                })
        ssh.close()
    except Exception as e:
        msg = f"Connexion SSH échouée: {str(e)}"
        results = [{"id": fid, "title": rec.get(
            "name", "Unknown"), "success": False, "message": msg} for fid, rec, _ in fixes]

    return results

# Exécution des correctifs WinRM en batch
def execute_winrm_batch(fixes: List[Tuple[int, Dict, str]]) -> List[Dict]:
    results = []
    for fix_id, rec, command in fixes:
        try:
            stdout, stderr = run_ps(command)
            results.append({
                "id": fix_id,
                "title": rec.get("name", "Unknown"),
                "success": not stderr.strip(),
                "message": (stdout or stderr or "Exécuté avec succès").strip()[:500]
            })
        except Exception as e:
            results.append({
                "id": fix_id,
                "title": rec.get("name", "Unknown"),
                "success": False,
                "message": f"Erreur WinRM: {str(e)}"
            })
    return results

# Route d'exécution de multiples correctifs
# Exécuter plusieurs correctifs sélectionnés
@app.route("/execute-multiple-fixes", methods=["POST"])
def execute_multiple_fixes():
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 400

    data = request.get_json()
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "message": "Aucun ID de correctif spécifié"}), 400

    try:
        ids = [int(i) for i in ids]
    except ValueError:
        return jsonify({"success": False, "message": "IDs invalides"}), 400

    if not RECOMMENDATIONS_CACHE:
        return jsonify({"success": False, "message": "Aucune recommandation disponible"}), 400

    # Séparer les correctifs SSH et WinRM
    ssh_fixes, winrm_fixes = [], []
    valid_fixes = [RECOMMENDATIONS_CACHE[i]
                   for i in ids if 0 <= i < len(RECOMMENDATIONS_CACHE)]

    for idx, rec in zip(ids, valid_fixes):
        cmd = rec.get("command_template")
        if not cmd:
            continue
        service = rec.get("service", "").lower()
        if "ssh" in service:
            ssh_fixes.append((idx, rec, cmd))
        else:
            winrm_fixes.append((idx, rec, cmd))

    results = []
    if ssh_fixes:
        results.extend(execute_ssh_batch(ssh_fixes))
    if winrm_fixes:
        results.extend(execute_winrm_batch(winrm_fixes))

    results.sort(key=lambda x: x["id"])

    successful = sum(1 for r in results if r.get("success"))
    if successful:
        try:
            # Envoyer une alerte SNS si des correctifs ont été appliqués avec succès
            send_sns_alert(
                subject="[CyberAudit] Correctifs exécutés",
                message=f"{successful}/{len(results)} correctifs exécutés avec succès."
            )
        except Exception as e:
            app.logger.warning(f"SNS notification failed: {str(e)}")

    return jsonify({
        "success": True,
        "results": results,
        "summary": {
            "total": len(results),
            "successful": successful,
            "failed": len(results) - successful
        }
    })

# ========================
# History & Export Routes
# ========================

# Route de la vue historique
# Afficher la liste des audits historiques
@app.route("/history")
def history_view():
    table = get_dynamodb_table()
    response = table.scan()
    audits = sorted(response.get("Items", []),
                    key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template("history.html", audits=audits)

# Route des détails d'un audit historique
# Afficher les détails d'un audit historique
@app.route("/history/<audit_id>")
def history_details(audit_id):
    table = get_dynamodb_table()
    response = table.get_item(Key={"audit_id": audit_id})
    if "Item" not in response:
        return render_template("history_details.html", audit=None)

    audit = normalize_audit_data(response["Item"])
    return render_template("history_details.html", audit=audit)
# Routes d'exportation des audits historiques
# Exporter l'audit historique au format CSV
@app.route("/history/<audit_id>/export/csv")
def export_history_csv(audit_id):
    table = get_dynamodb_table()
    response = table.get_item(Key={"audit_id": audit_id})
    if "Item" not in response:
        return "Audit introuvable", 404

    audit = normalize_audit_data(response["Item"])
    recommendations = build_recommendations(audit.get("all_data", {}))

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Vulnérabilité", "Sévérité",
                    "Service", "Affecte", "Commande"])

    for rec in recommendations:
        writer.writerow([
            rec.get("name", ""),
            rec.get("severity", ""),
            rec.get("service", ""),
            ", ".join(rec.get("affected", [])),
            rec.get("command_template") or "(Aucun correctif auto)"
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Disposition"] = f"attachment; filename=audit_{audit_id}.csv"
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    return resp

# Exporter l'audit historique au format HTML
# Route d'exportation de l'audit historique au format HTML
@app.route("/history/<audit_id>/export/html")
def export_history_html(audit_id):
    table = get_dynamodb_table()
    response = table.get_item(Key={"audit_id": audit_id})
    if "Item" not in response:
        return "Audit introuvable", 404

    audit = normalize_audit_data(response["Item"])
    recommendations = build_recommendations(audit["all_data"])

    html = render_template("report_template.html",
                           audit=audit, recs=recommendations)
    resp = make_response(html)
    resp.headers["Content-Disposition"] = f"attachment; filename=audit_{audit_id}.html"
    resp.headers["Content-Type"] = "text/html"
    return resp

# Route de test SNS
@app.route("/sns-test", methods=["POST"])
# Tester la configuration SNS en envoyant une alerte de test
def sns_test():
    ok = send_sns_alert(
        subject="[CyberAudit] Test Alert",
        message="SNS is correctly configured. This is a test alert."
    )
    return jsonify({
        "success": ok,
        "message": "SNS test alert sent!" if ok else "SNS not configured or failed."
    })
