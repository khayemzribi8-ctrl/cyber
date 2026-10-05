"""
Compliance mapping engine.

Correlates findings to representative controls across CIS, NIST CSF,
NIST 800-53, ISO 27001 and SOC 2. This is an *assistive* mapping to speed up
evidence gathering — it does not assert or claim formal certification.

Control status logic
---------------------
For each control (mapped to one or more modules):
  * FAIL         - at least one OPEN finding of MEDIUM+ severity in a mapped module
  * PARTIAL      - only LOW / INFO open findings in a mapped module
  * PASS         - a mapped module was assessed and has no open MEDIUM+ finding
  * NOT ASSESSED - none of the mapped modules produced findings this audit
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Set

from .models import Finding, FindingStatus, Severity

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "compliance.json")

_OPEN = {FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value,
         FindingStatus.IN_PROGRESS.value}


@lru_cache(maxsize=1)
def _load() -> Dict[str, Any]:
    with open(_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def frameworks() -> List[str]:
    return _load().get("frameworks", [])


def evaluate(findings: List[Finding]) -> Dict[str, Any]:
    """Return per-control status and per-framework rollups."""
    cfg = _load()

    # index open findings by module
    by_module: Dict[str, List[Finding]] = {}
    assessed_modules: Set[str] = set()
    for f in findings:
        by_module.setdefault(f.module, []).append(f)
        assessed_modules.add(f.module)

    controls_out: List[Dict[str, Any]] = []
    for ctrl in cfg.get("controls", []):
        mods = ctrl.get("modules", [])
        related = [f for m in mods for f in by_module.get(m, [])]
        assessed = any(m in assessed_modules for m in mods)

        open_related = [f for f in related if f.status in _OPEN]
        med_plus = [f for f in open_related if f.severity_enum.rank >= Severity.MEDIUM.rank]
        low_only = [f for f in open_related if 0 < f.severity_enum.rank < Severity.MEDIUM.rank]

        if not assessed:
            status = "NOT ASSESSED"
        elif med_plus:
            status = "FAIL"
        elif low_only:
            status = "PARTIAL"
        else:
            status = "PASS"

        controls_out.append({
            "framework": ctrl["framework"],
            "control": ctrl["control"],
            "requirement": ctrl["requirement"],
            "modules": mods,
            "status": status,
            "finding_count": len(open_related),
            "findings": [f.id for f in open_related],
            "max_severity": max((f.severity_enum.value for f in open_related),
                                key=lambda s: Severity.coerce(s).rank, default=""),
        })

    # per framework rollup
    fw_roll: Dict[str, Dict[str, int]] = {}
    for c in controls_out:
        r = fw_roll.setdefault(c["framework"], {"PASS": 0, "PARTIAL": 0,
                                                "FAIL": 0, "NOT ASSESSED": 0, "total": 0})
        r[c["status"]] += 1
        r["total"] += 1
    for fw, r in fw_roll.items():
        assessed = r["total"] - r["NOT ASSESSED"]
        r["assessed"] = assessed
        r["coverage_pct"] = round(100.0 * assessed / r["total"], 1) if r["total"] else 0.0
        graded = r["PASS"] + 0.5 * r["PARTIAL"]
        r["pass_pct"] = round(100.0 * graded / assessed, 1) if assessed else 0.0

    # a small compliance penalty fed into the security score
    fails = sum(1 for c in controls_out if c["status"] == "FAIL")
    penalty = min(fails * 1.0, 10.0)

    return {
        "controls": controls_out,
        "frameworks": fw_roll,
        "penalty": penalty,
        "summary": {
            "total": len(controls_out),
            "fail": fails,
            "pass": sum(1 for c in controls_out if c["status"] == "PASS"),
            "partial": sum(1 for c in controls_out if c["status"] == "PARTIAL"),
            "not_assessed": sum(1 for c in controls_out if c["status"] == "NOT ASSESSED"),
        },
    }
