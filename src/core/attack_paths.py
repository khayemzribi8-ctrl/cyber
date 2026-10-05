"""
Attack-path analysis.

Builds evidence-linked attack paths from the actual findings. Each path node is
labelled with a confidence class so the UI never over-claims exploitability:

    * observed  - the enabling condition was directly observed in a finding
    * potential - a plausible next step given observed conditions
    * inferred  - a generic escalation step included for context only

A path is only emitted when its *first* (entry) condition is backed by a real
finding. Downstream nodes are clearly marked ``potential`` / ``inferred``.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import Finding, Severity

# ordered chain templates: each stage lists (label, tactic, technique, signatures/keywords)
# a stage is "observed" when a finding matches its keywords.
_TEMPLATES = [
    {
        "name": "Exposed remote access to foothold",
        "stages": [
            {"label": "Reachable remote-admin service", "tactic": "Initial Access",
             "technique": "T1021", "match": ["NET_RDP_EXPOSED", "NET_WINRM_EXPOSED",
             "NET_SSH_EXPOSED", "rdp", "winrm", "ssh exposure", "exposed"]},
            {"label": "Weak / valid account", "tactic": "Initial Access",
             "technique": "T1078", "match": ["password never expires", "n'expire",
             "mfa", "passwordauthentication", "weak", "sans expiration"]},
            {"label": "Interactive session on host", "tactic": "Execution",
             "technique": "T1059", "match": [], "min": "potential"},
        ],
    },
    {
        "name": "Kerberos credential theft to privilege escalation",
        "stages": [
            {"label": "Kerberoastable / AS-REP account", "tactic": "Credential Access",
             "technique": "T1558", "match": ["kerberoast", "spn", "pre-auth", "preauth", "as-rep"]},
            {"label": "Offline crack / ticket abuse", "tactic": "Credential Access",
             "technique": "T1550", "match": ["unconstrained", "délégation", "delegation", "rbcd"],
             "min": "potential"},
            {"label": "Privileged domain account", "tactic": "Privilege Escalation",
             "technique": "T1078.002", "match": ["domain admins", "privileged", "adminsdholder"]},
            {"label": "Domain dominance", "tactic": "Impact",
             "technique": "T1003.006", "match": ["dcsync", "replicating"], "min": "inferred"},
        ],
    },
    {
        "name": "Token abuse to local SYSTEM",
        "stages": [
            {"label": "Impersonation privilege held", "tactic": "Privilege Escalation",
             "technique": "T1134.001", "match": ["seimpersonate", "seassignprimarytoken", "potato"]},
            {"label": "Service / spooler abuse", "tactic": "Privilege Escalation",
             "technique": "T1068", "match": ["spooler", "printnightmare"], "min": "potential"},
            {"label": "SYSTEM on host", "tactic": "Privilege Escalation",
             "technique": "T1134", "match": [], "min": "inferred"},
        ],
    },
    {
        "name": "ADCS certificate abuse to domain compromise",
        "stages": [
            {"label": "Vulnerable certificate template / CA", "tactic": "Credential Access",
             "technique": "T1649", "match": ["adcs", "certificate template", "esc"]},
            {"label": "Forge authentication certificate", "tactic": "Credential Access",
             "technique": "T1649", "match": [], "min": "potential"},
            {"label": "Authenticate as privileged principal", "tactic": "Privilege Escalation",
             "technique": "T1078.002", "match": ["domain admins", "privileged"], "min": "inferred"},
        ],
    },
]


def _match_findings(findings: List[Finding], keywords: List[str]) -> List[Finding]:
    if not keywords:
        return []
    kws = [k.lower() for k in keywords]
    hits = []
    for f in findings:
        hay = (f.signature + " " + f.title + " " + f.description).lower()
        if any(k in hay for k in kws):
            hits.append(f)
    return hits


def build_paths(findings: List[Finding]) -> List[Dict[str, Any]]:
    open_findings = [f for f in findings if f.severity_enum.rank >= Severity.LOW.rank]
    paths: List[Dict[str, Any]] = []

    for tmpl in _TEMPLATES:
        nodes: List[Dict[str, Any]] = []
        entry_observed = False
        any_observed = False
        for idx, stage in enumerate(tmpl["stages"]):
            hits = _match_findings(open_findings, stage.get("match", []))
            if hits:
                status = "observed"
                any_observed = True
                if idx == 0:
                    entry_observed = True
            else:
                status = stage.get("min", "inferred")
            nodes.append({
                "label": stage["label"],
                "tactic": stage["tactic"],
                "technique": stage["technique"],
                "status": status,
                "evidence": [
                    {"id": f.id, "title": f.title, "asset": f.asset,
                     "severity": f.severity_enum.value}
                    for f in hits[:6]
                ],
            })
        # only emit a path whose entry condition is real
        if entry_observed and any_observed:
            severities = [
                f.severity_enum.rank
                for stage in tmpl["stages"]
                for f in _match_findings(open_findings, stage.get("match", []))
            ]
            paths.append({
                "name": tmpl["name"],
                "nodes": nodes,
                "observed_stages": sum(1 for n in nodes if n["status"] == "observed"),
                "total_stages": len(nodes),
                "max_severity": Severity(
                    _rank_to_sev(max(severities))).value if severities else "INFO",
            })

    paths.sort(key=lambda p: (-p["observed_stages"],
                              -Severity.coerce(p["max_severity"]).rank))
    return paths


def _rank_to_sev(rank: int) -> str:
    for s in Severity:
        if s.rank == rank:
            return s.value
    return Severity.INFO.value
