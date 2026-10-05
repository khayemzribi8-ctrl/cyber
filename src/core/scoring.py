"""
Transparent security-scoring engine.

The score is deterministic and fully explainable. It is NOT a random number:
every point lost or gained is itemised in the returned ``breakdown`` so the
UI can show the user *why* their score is what it is.

Formula (documented)
---------------------
    score = 100
            - min(CRIT_count * 10, 40)      # critical findings
            - min(HIGH_count * 5,  25)      # high findings
            - min(MED_count  * 2,  20)      # medium findings
            - min(LOW_count  * 0.5, 8)      # low findings
            - min(exposed_admin_services * 3, 15)   # reachable RDP/WinRM/SSH/SMB
            + min(remediated_count * 1.5, 10)       # credit for fixed issues
    score = clamp(round(score), 0, 100)

Only findings whose status is OPEN / ACKNOWLEDGED / IN_PROGRESS count as
"open" risk. REMEDIATED findings give credit; FALSE_POSITIVE and ACCEPTED_RISK
are excluded from penalties.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import Finding, FindingStatus, Severity

WEIGHTS = {
    Severity.CRITICAL: (10.0, 40.0),
    Severity.HIGH: (5.0, 25.0),
    Severity.MEDIUM: (2.0, 20.0),
    Severity.LOW: (0.5, 8.0),
}
EXPOSURE_PER = 3.0
EXPOSURE_CAP = 15.0
REMEDIATION_PER = 1.5
REMEDIATION_CAP = 10.0

_OPEN_STATES = {
    FindingStatus.OPEN.value,
    FindingStatus.ACKNOWLEDGED.value,
    FindingStatus.IN_PROGRESS.value,
}

# module groups -> posture domains
_DOMAIN_MAP = {
    "Active Directory": "AD Security",
    "Kerberos": "AD Security",
    "LDAP": "AD Security",
    "Identity Security": "Identity",
    "Network": "Network",
    "Windows Security": "Windows",
    "SMB": "Windows",
    "RDP": "Windows",
    "WinRM": "Windows",
    "Linux": "Linux",
    "ADCS": "ADCS",
    "Cloud": "AWS",
    "Vulnerability Management": "Network",
    "Security Operations": "Identity",
}
DOMAINS = ["AD Security", "Identity", "Network", "Windows", "Linux", "ADCS", "AWS", "Compliance"]


def _is_open(f: Finding) -> bool:
    return f.status in _OPEN_STATES


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def _exposed_admin_services(findings: List[Finding]) -> int:
    """Count reachable remote-admin exposure findings (network collector)."""
    n = 0
    for f in findings:
        if not _is_open(f):
            continue
        hay = (f.signature + " " + f.title).upper()
        if any(k in hay for k in ("NET_RDP_EXPOSED", "NET_WINRM_EXPOSED",
                                   "NET_SSH_EXPOSED", "NET_SMB_EXPOSED")):
            n += 1
    return n


def security_score(findings: List[Finding],
                   compliance_penalty: float = 0.0) -> Dict[str, Any]:
    """Compute the overall security score with an itemised breakdown."""
    counts = {s: 0 for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)}
    remediated = 0
    for f in findings:
        if f.status == FindingStatus.REMEDIATED.value:
            remediated += 1
            continue
        if not _is_open(f):
            continue
        sev = f.severity_enum
        if sev in counts:
            counts[sev] += 1

    score = 100.0
    breakdown: List[Dict[str, Any]] = []

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        per, cap = WEIGHTS[sev]
        raw = counts[sev] * per
        penalty = min(raw, cap)
        if counts[sev]:
            score -= penalty
            breakdown.append({
                "label": f"{counts[sev]} {sev.value.title()} finding"
                         + ("s" if counts[sev] != 1 else ""),
                "delta": -round(penalty),
                "kind": "penalty",
                "capped": raw > cap,
            })

    exposed = _exposed_admin_services(findings)
    if exposed:
        pen = min(exposed * EXPOSURE_PER, EXPOSURE_CAP)
        score -= pen
        breakdown.append({
            "label": f"{exposed} exposed remote-admin service"
                     + ("s" if exposed != 1 else ""),
            "delta": -round(pen), "kind": "penalty",
            "capped": exposed * EXPOSURE_PER > EXPOSURE_CAP,
        })

    if compliance_penalty:
        pen = min(compliance_penalty, 10.0)
        score -= pen
        breakdown.append({
            "label": "Compliance control gaps",
            "delta": -round(pen), "kind": "penalty", "capped": False,
        })

    if remediated:
        bonus = min(remediated * REMEDIATION_PER, REMEDIATION_CAP)
        score += bonus
        breakdown.append({
            "label": f"{remediated} remediated finding"
                     + ("s" if remediated != 1 else ""),
            "delta": round(bonus), "kind": "bonus", "capped": False,
        })

    score = max(0, min(100, round(score)))
    return {
        "score": score,
        "grade": grade(score),
        "breakdown": breakdown,
        "counts": {k.value: v for k, v in counts.items()},
        "remediated": remediated,
        "exposed_admin_services": exposed,
    }


def posture(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Per-domain posture scores (0-100) for the dashboard radar/bars."""
    domain_findings: Dict[str, List[Finding]] = {d: [] for d in DOMAINS}
    for f in findings:
        # module group is resolved from the module registry lazily to avoid
        # a hard import cycle
        from .registry import get_module
        mod = get_module(f.module)
        group = mod.group if mod else ""
        domain = _DOMAIN_MAP.get(group)
        if domain:
            domain_findings[domain].append(f)
        if f.compliance:
            domain_findings["Compliance"].append(f)

    out = []
    for d in DOMAINS:
        fs = domain_findings[d]
        if not fs and d != "Compliance":
            out.append({"domain": d, "score": None, "findings": 0,
                        "assessed": False})
            continue
        sub = security_score(fs)
        out.append({
            "domain": d,
            "score": sub["score"],
            "grade": sub["grade"],
            "findings": sum(1 for f in fs if _is_open(f)),
            "assessed": bool(fs),
        })
    return out
