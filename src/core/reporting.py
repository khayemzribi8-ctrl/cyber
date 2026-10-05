"""
Report builders: CSV, JSON, HTML and (optional) PDF.

HTML/PDF reuse the Flask template ``report.html`` so the report matches the
platform look. PDF is only available when the optional ``weasyprint`` package
is installed; otherwise the caller falls back to HTML.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Callable, Dict


def build_csv(d: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Finding ID", "Title", "Severity", "Status", "Category", "Module",
                "Asset", "Asset IP", "MITRE", "Tactics", "Confidence", "CVE",
                "Compliance", "Detection Source"])
    for f in sorted(d["findings"], key=lambda x: -x.severity_enum.rank):
        w.writerow([
            f.id, f.title, f.severity, f.status, f.category, f.module,
            f.asset, f.asset_ip,
            "; ".join(m.technique_id for m in f.mitre),
            "; ".join(sorted({m.tactic for m in f.mitre if m.tactic})),
            f.confidence, f.cve,
            "; ".join(f"{c['framework']}:{c['control']}" for c in (f.compliance or [])),
            f.detection_source,
        ])
    return buf.getvalue()


def build_json(d: Dict[str, Any]) -> str:
    run = d["audit"]
    payload = {
        "audit": run.to_dict() if run else None,
        "security_score": d["score"],
        "summary": d["summary"],
        "coverage": {k: v for k, v in d["coverage"].items()
                     if k in ("observed_count", "total_techniques", "coverage_pct")},
        "compliance": d["compliance"]["summary"],
        "posture": d["posture"],
        "attack_paths": d["attack_paths"],
        "assets": [a.to_dict() for a in d["assets"]],
        "findings": [f.to_dict() for f in d["findings"]],
        "disclaimer": "Compliance mappings are assistive and do not assert formal certification.",
    }
    return json.dumps(payload, indent=2, default=str)


def build_html(d: Dict[str, Any], render_template: Callable) -> str:
    return render_template("report.html", d=d, standalone=True)


def build_pdf(d: Dict[str, Any], render_template: Callable):
    try:
        from weasyprint import HTML  # optional
    except Exception:
        return None
    html = build_html(d, render_template)
    return HTML(string=html).write_pdf()
