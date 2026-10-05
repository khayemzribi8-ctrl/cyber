#!/usr/bin/env python3
"""
Sentinel Security Assessment Platform — unified CLI.

The CLI and the web dashboard share the same audit engine (src/core/engine.py),
so results are identical whichever interface is used.

Subcommands
-----------
  audit       Run an assessment (all modules or a subset)
  findings    List findings from the latest assessment
  assets      List discovered assets
  mitre       Show ATT&CK coverage
  report      Export a report (html|csv|json|pdf)
  remediate   Preview (or, with --execute, run allow-listed) remediation

Legacy flags (--all / --ldap / --ssh / --ad / --target / --report) are still
accepted and mapped onto the new engine so existing scripts keep working.

Examples
--------
  python src/main.py audit --all --target 10.0.0.10
  python src/main.py audit --module network --module ad
  python src/main.py findings --severity CRITICAL
  python src/main.py mitre
  python src/main.py report --format html --out report.html
  python src/main.py --all --report both        # legacy form
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config import load_env                       # noqa: E402
from core.engine import ALL_COLLECTOR_KEYS, run_audit, collector_status  # noqa: E402
from core.store import get_store                        # noqa: E402
from core.mitre import get_engine as get_mitre          # noqa: E402

LEGACY_TO_MODULES = {
    "ldap": ["ldap"], "ssh": ["ssh"], "ad": ["ad", "kerberos", "privilege"],
    "aws": ["aws"], "network": ["network"],
}


def _p(msg=""):
    print(msg)


def cmd_audit(args) -> int:
    load_env()
    modules = None
    if getattr(args, "all", False):
        modules = ALL_COLLECTOR_KEYS
    elif getattr(args, "module", None):
        modules = []
        for m in args.module:
            modules.extend(LEGACY_TO_MODULES.get(m, [m]))
    else:
        # legacy single-flag form
        legacy = [k for k in ("ldap", "ssh", "ad", "aws", "network")
                  if getattr(args, k, False)]
        if legacy:
            modules = []
            for m in legacy:
                modules.extend(LEGACY_TO_MODULES[m])
    if not modules:
        modules = ALL_COLLECTOR_KEYS

    _p(f"Running assessment · modules={modules} · target={args.target or '(env default)'}")

    def prog(stage, st):
        if st == "running":
            _p(f"  → {stage} ...")
    res = run_audit(modules=modules, target=args.target or "", triggered_by="cli",
                    persist=True, progress=prog)
    sc = res["score"]
    s = res["audit"].summary
    _p("")
    _p(f"Assessment {res['audit'].audit_id} complete.")
    _p(f"  Security score : {sc['score']}/100 ({sc['grade']})")
    _p(f"  Findings       : {s.get('TOTAL',0)} "
       f"(CRIT {s.get('CRITICAL',0)}, HIGH {s.get('HIGH',0)}, "
       f"MED {s.get('MEDIUM',0)}, LOW {s.get('LOW',0)})")
    _p(f"  ATT&CK         : {res['coverage']['observed_count']} techniques "
       f"({res['coverage']['coverage_pct']}% coverage)")
    _p(f"  Assets         : {len(res['assets'])}")
    for m in res["module_status"]:
        if m["status"] != "ok":
            _p(f"  [!] {m['key']}: {m['status']} — {m.get('reason','')}")

    if getattr(args, "report", None) and args.report != "none":
        _export(res["audit"].audit_id, args.report, getattr(args, "out", None))
    return 0


def _latest():
    aid = get_store().latest_audit_id()
    if not aid:
        _p("No assessment found. Run:  python src/main.py audit --all")
        return None, []
    return aid, get_store().get_findings(aid)


def cmd_findings(args) -> int:
    aid, findings = _latest()
    if aid is None:
        return 1
    if args.severity:
        findings = [f for f in findings if f.severity == args.severity]
    findings.sort(key=lambda f: -f.severity_enum.rank)
    _p(f"{'SEVERITY':<9} {'MODULE':<26} {'ASSET':<14} MITRE   TITLE")
    for f in findings:
        mit = ",".join(m.technique_id for m in f.mitre[:2])
        _p(f"{f.severity:<9} {f.module:<26} {(f.asset or '-'):<14} {mit:<7} {f.title[:60]}")
    _p(f"\n{len(findings)} findings.")
    return 0


def cmd_assets(args) -> int:
    aid, _ = _latest()
    if aid is None:
        return 1
    assets = get_store().get_assets(aid)
    _p(f"{'HOST':<18} {'TYPE':<20} {'RISK':<5} PORTS")
    for a in assets:
        _p(f"{a.hostname:<18} {a.asset_type:<20} {a.risk_score:<5} "
           f"{','.join(str(p) for p in a.open_ports)}")
    _p(f"\n{len(assets)} assets.")
    return 0


def cmd_mitre(args) -> int:
    aid, findings = _latest()
    if aid is None:
        return 1
    cov = get_mitre().coverage(findings)
    _p(f"ATT&CK coverage: {cov['observed_count']}/{cov['total_techniques']} "
       f"techniques ({cov['coverage_pct']}%) across {cov['tactic_count']} tactics\n")
    for e in cov["observed_techniques"]:
        _p(f"  {e['id']:<11} {e['name'][:46]:<46} {e['tactic']:<20} "
           f"{e['findings']} finding(s)")
    return 0


def _export(aid, fmt, out):
    from core.reporting import build_csv, build_json
    from core.compliance import evaluate as ev
    from core.scoring import security_score, posture
    from core.attack_paths import build_paths
    findings = get_store().get_findings(aid)
    comp = ev(findings)
    d = {"audit": get_store().get_audit(aid), "findings": findings,
         "assets": get_store().get_assets(aid),
         "score": security_score(findings, compliance_penalty=comp["penalty"]),
         "compliance": comp, "posture": posture(findings),
         "coverage": get_mitre().coverage(findings), "attack_paths": build_paths(findings),
         "summary": get_store().get_audit(aid).summary, "has_data": True}
    fmts = ["html", "csv", "json"] if fmt == "both" else [fmt]
    for f in fmts:
        if f == "csv":
            data = build_csv(d)
        elif f == "json":
            data = build_json(d)
        elif f == "html":
            data = _render_html(d)
        else:
            continue
        path = out or f"report_{aid}.{f}"
        if fmt == "both":
            path = f"report_{aid}.{f}"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
        _p(f"  Report written: {path}")


def _render_html(d):
    """Render the standalone HTML report outside a request context."""
    from webapp import create_app
    app = create_app()
    with app.test_request_context():
        from flask import render_template
        return render_template("report.html", d=d, standalone=True)


def cmd_report(args) -> int:
    aid, _ = _latest()
    if aid is None:
        return 1
    _export(aid, args.format, args.out)
    return 0


def cmd_remediate(args) -> int:
    aid, findings = _latest()
    if aid is None:
        return 1
    from webapp.remediation import build_remediation_items, execute_command
    items = build_remediation_items(findings)
    if args.finding:
        items = [it for it in items if it["finding"].id == args.finding]
    for it in items:
        f = it["finding"]
        _p(f"[{f.severity}] {f.id} {f.problem}")
        _p(f"    fix: {it['fix_description']}")
        if it["command"]:
            _p(f"    cmd: {it['command'][:120]}")
            _p(f"    allow-listed: {it['auto_fixable']}")
        if args.execute and it["auto_fixable"]:
            res = execute_command(f, args.channel)
            _p(f"    EXECUTE -> ok={res['ok']} {res['message'][:120]}")
        _p("")
    if args.execute:
        _p("Note: only allow-listed commands are executed; others are preview-only.")
    return 0


def cmd_collectors(args) -> int:
    for c in collector_status():
        _p(f"{c['key']:<20} {'READY' if c['available'] else 'UNAVAILABLE':<12} {c['reason']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="Run an assessment")
    a.add_argument("--all", action="store_true")
    a.add_argument("--module", action="append", help="collector key (repeatable)")
    a.add_argument("--target", default="")
    a.add_argument("--report", choices=["html", "csv", "json", "both", "none"], default="none")
    a.add_argument("--out")
    for legacy in ("ldap", "ssh", "ad", "aws", "network"):
        a.add_argument(f"--{legacy}", action="store_true", help=argparse.SUPPRESS)
    a.set_defaults(func=cmd_audit)

    f = sub.add_parser("findings", help="List findings")
    f.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"])
    f.set_defaults(func=cmd_findings)

    sub.add_parser("assets", help="List assets").set_defaults(func=cmd_assets)
    sub.add_parser("mitre", help="ATT&CK coverage").set_defaults(func=cmd_mitre)
    sub.add_parser("collectors", help="Show collector availability").set_defaults(func=cmd_collectors)

    r = sub.add_parser("report", help="Export a report")
    r.add_argument("--format", choices=["html", "csv", "json", "both"], default="html")
    r.add_argument("--out")
    r.set_defaults(func=cmd_report)

    rm = sub.add_parser("remediate", help="Preview/execute remediation")
    rm.add_argument("--finding")
    rm.add_argument("--execute", action="store_true")
    rm.add_argument("--channel", choices=["winrm", "ssh"], default="winrm")
    rm.set_defaults(func=cmd_remediate)
    return p


def main() -> int:
    argv = sys.argv[1:]
    # legacy compatibility: `main.py --all ...` -> `main.py audit --all ...`
    if argv and argv[0].startswith("-"):
        argv = ["audit"] + argv
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
