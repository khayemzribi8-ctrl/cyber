"""
Normalization layer.

Converts collector output (legacy auditor dicts or already-built Finding
objects) into the standardized :class:`Finding` model, classifies each into a
registry module, sets its category, attaches compliance references and enriches
it with MITRE ATT&CK techniques.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List

from .compliance import _load as _load_compliance
from .mitre import get_engine
from .models import Finding
from .registry import classify, get_module


# phrases that indicate a collector could not reach / authenticate to the target
# rather than a genuine security weakness. These are reclassified to INFO so they
# do not fabricate a CRITICAL finding or drag down the security score.
_CONNECTIVITY_MARKERS = (
    "socket connection error", "winerror 10061", "actively refused",
    "connection refused", "connection error", "could not connect",
    "unable to connect", "connection timed out", "timed out", "unreachable",
    "getaddrinfo", "name or service not known", "no route to host",
    "connection reset", "errno", "invalidcredentials", "invalid credentials",
    "impossible de déterminer le base dn", "impossible de déduire",
    "could not read sshd_config", "connexion ssh", "ad connection",
    "ldap connection error", "connexion ad",
    # generic collector-failure markers (title usually ends in "error")
    "scan error", "audit error", "surface scan error", "unexpected error",
    "exception inattendue",
    # AWS auth / token errors
    "invalidclienttokenid", "security token", "expiredtoken",
    "unrecognizedclientexception", "signaturedoesnotmatch",
    "access denied", "access is denied",
    "unable to locate credentials", "nocredentialserror", "botocoreerror",
)


def _is_connectivity_error(f: "Finding") -> bool:
    hay = (f.title + " " + f.description).lower()
    return any(m in hay for m in _CONNECTIVITY_MARKERS)


@lru_cache(maxsize=1)
def _module_to_controls() -> Dict[str, List[Dict[str, str]]]:
    idx: Dict[str, List[Dict[str, str]]] = {}
    for ctrl in _load_compliance().get("controls", []):
        for m in ctrl.get("modules", []):
            idx.setdefault(m, []).append({
                "framework": ctrl["framework"],
                "control": ctrl["control"],
                "requirement": ctrl["requirement"],
            })
    return idx


def normalize(
    collector_key: str,
    items: List[Any],
    asset: str = "",
    asset_ip: str = "",
    audit_id: str = "",
) -> List[Finding]:
    """Normalize a collector's raw output into enriched Findings."""
    findings: List[Finding] = []
    enrichable: List[Finding] = []
    for item in items or []:
        if isinstance(item, Finding):
            f = item
        elif isinstance(item, dict):
            f = Finding.from_legacy(item, module=collector_key,
                                    detection_source=collector_key,
                                    asset=asset, asset_ip=asset_ip)
        else:
            continue

        # A collector that cannot reach/authenticate to the target is an
        # OPERATIONAL issue, not a critical security finding. Reclassify it so it
        # is honest, does not affect the security score, and is not mapped to
        # ATT&CK techniques.
        if _is_connectivity_error(f):
            from .models import FindingStatus, Severity
            f.severity = Severity.INFO.value
            f.status = FindingStatus.OPEN.value
            f.module = "collector_diagnostics"
            f.category = "Security Operations"
            f.signature = f"{collector_key.upper()}_UNREACHABLE"
            f.mitre = []
            f.remediation = None
            if not f.title.lower().startswith("collector could not connect"):
                f.title = (f"Collector '{collector_key}' could not connect to target "
                           f"— {f.title}")
            f.risk = ("Operational: the collector could not reach or authenticate to "
                      "the target (not a security weakness). Verify the host is correct, "
                      "the required port is reachable, and credentials are configured.")
            if audit_id:
                f.audit_id = audit_id
                for ev in f.evidence:
                    ev.audit_id = audit_id
            findings.append(f)
            continue

        # classify into a registry module
        haystack = " ".join([f.title, f.signature, f.category, f.description])
        module_key = classify(collector_key, haystack, signature=f.signature)
        f.module = module_key
        mod = get_module(module_key)
        if mod:
            f.category = mod.group
        if not f.asset and asset:
            f.asset = asset
        if not f.asset_ip and asset_ip:
            f.asset_ip = asset_ip
        if audit_id:
            f.audit_id = audit_id
            for ev in f.evidence:
                ev.audit_id = audit_id

        # attach compliance references for this module
        controls = _module_to_controls().get(module_key, [])
        if controls:
            f.compliance = controls

        findings.append(f)
        enrichable.append(f)

    # MITRE enrichment (config-driven, centralized) — connectivity errors are
    # excluded so they are never mapped to ATT&CK techniques.
    get_engine().enrich(enrichable)
    return findings
