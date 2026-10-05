#!/usr/bin/env python3
import argparse
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd
from utils.config import load_env, str2bool
from report.generator import render_html, export_csv
from auditors import audit_ldap, audit_ssh, audit_ad

# construire les sections du rapport


def build_sections(findings_map: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Transform audit findings into report sections."""
    return [
        {"title": f"{module} Findings", "findings": items}
        for module, items in findings_map.items()
        if items  # Only include modules with actual findings
    ]

# les commande line arguments


def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Cyber Audit Tool - Audit LDAP, SSH and Active Directory configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --all                     # Run all audits, generate HTML report
  python main.py --ldap --ssh --report both # Run LDAP + SSH, generate HTML + CSV
  python main.py --ad --report csv          # Only AD audit, CSV output
        """
    )

    # les options globales
    parser.add_argument(
        "--target",
        default=os.environ.get("LDAP_HOST", "127.0.0.1"),
        help="Target host/IP for LDAP and SSH audits (default: %(default)s)"
    )
    parser.add_argument(
        "--out",
        default="outputs",
        help="Output directory for reports (default: %(default)s)"
    )
    parser.add_argument(
        "--report",
        choices=["html", "csv", "both"],
        default="html",
        help="Report format: html, csv, or both (default: %(default)s)"
    )

    # la selection des audits
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true",
                       help="Run all available audits")
    group.add_argument(
        "--ldap", action="store_true", help="Run only LDAP audit"
    )
    group.add_argument(
        "--ssh", action="store_true", help="Run only SSH audit"
    )
    group.add_argument(
        "--ad", action="store_true", help="Run only Active Directory audit"
    )

    # Options LDAP
    parser.add_argument("--ldap-port", type=int,
                        default=int(os.environ.get("LDAP_PORT", 389)))
    parser.add_argument("--ldap-ssl", type=str,
                        default=os.environ.get("LDAP_SSL", "false"))
    parser.add_argument(
        "--ldap-bind-dn", default=os.environ.get("LDAP_BIND_DN", ""))
    parser.add_argument("--ldap-password",
                        default=os.environ.get("LDAP_PASSWORD", ""))
    parser.add_argument(
        "--ldap-base-dn", default=os.environ.get("LDAP_BASE_DN", ""))

    # Options SSH
    parser.add_argument("--ssh-port", type=int,
                        default=int(os.environ.get("SSH_PORT", 22)))
    parser.add_argument(
        "--ssh-username", default=os.environ.get("SSH_USERNAME", ""))
    parser.add_argument(
        "--ssh-password", default=os.environ.get("SSH_PASSWORD", ""))
    parser.add_argument(
        "--ssh-key", default=os.environ.get("SSH_KEY_PATH", ""))

    # Option Active Directory
    parser.add_argument("--ad-domain", default=os.environ.get("AD_DOMAIN", ""))

    return parser.parse_args()

# point d'entree principal


def main() -> None:
    load_env()  # charger les variables d'environnement

    # parser les arguments
    args = parse_args()

    # determiner quels audits executer
    run_ldap = args.all or args.ldap
    run_ssh = args.all or args.ssh
    run_ad = args.all or args.ad

    if not (run_ldap or run_ssh or run_ad):
        print("No audit selected. Use --all or specify --ldap, --ssh, --ad")
        return

    findings: Dict[str, List[Dict[str, Any]]] = {}

    print("Starting security audit...\n")

    # lancer l'audit LDAP
    if run_ldap:
        print(f"Running LDAP audit on {args.target}:{args.ldap_port}...")
        try:
            findings["LDAP"] = audit_ldap.run(
                host=args.target,
                port=args.ldap_port,
                use_ssl=str2bool(args.ldap_ssl),
                bind_dn=args.ldap_bind_dn,
                base_dn=args.ldap_base_dn,
                password=args.ldap_password,
            )
            print("LDAP audit completed.\n")
        except Exception as e:
            print(f"LDAP audit failed: {e}\n")
            findings["LDAP"] = [
                {"check": "Connection Error", "result": str(e), "severity": "CRIT"}]

    # Lancer l'audit SSH
    if run_ssh:
        print(f"Running SSH audit on {args.target}:{args.ssh_port}...")
        try:
            findings["SSH"] = audit_ssh.run(
                host=args.target,
                port=args.ssh_port,
                username=args.ssh_username,
                password=args.ssh_password,
                key_path=args.ssh_key,
            )
            print("SSH audit completed.\n")
        except Exception as e:
            print(f"SSH audit failed: {e}\n")
            findings["SSH"] = [{"check": "Connection Error",
                                "result": str(e), "severity": "CRIT"}]

    # Lancer l'audit Active Directory
    if run_ad:
        print("Running Active Directory audit...")
    try:
        findings["Active Directory"] = audit_ad.run(
            host=args.target,           # ← Ajout obligatoire
            port=args.ldap_port,        # ← Ajout obligatoire
            domain=args.ad_domain,
            bind_dn=args.ldap_bind_dn,
            password=args.ldap_password,
        )
        print("Active Directory audit completed.\n")
    except Exception as e:
        print(f"AD audit failed: {e}\n")
        findings["Active Directory"] = [
            {"check": "Connection Error", "result": str(e), "severity": "CRIT"}]

    # preparer le repertoire de sortie
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out) / f"audit_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating reports in: {out_dir.resolve()}\n")

    # generation du rapport HTML
    if args.report in ("html", "both"):
        html_path = out_dir / "audit_report.html"
        render_html(
            sections=build_sections(findings),
            out_path=str(html_path),
            templates_dir="templates"
        )
        print(f"HTML report generated: {html_path.name}")

    # Generation du rapport CSV
    if args.report in ("csv", "both"):
        rows = []
        for module, items in findings.items():
            for item in items:
                row = {"Module": module}
                row.update(item)
                rows.append(row)

        if rows:
            df = pd.DataFrame(rows)
            csv_path = out_dir / "audit_report.csv"
            export_csv(df, str(csv_path))
            print(f"CSV report generated: {csv_path.name}")
        else:
            print("No findings to export to CSV.")

    print(f"\nAudit completed successfully!")
    print(f"Reports saved in: {out_dir.resolve()}")


# point d'entree principal
if __name__ == "__main__":
    main()
