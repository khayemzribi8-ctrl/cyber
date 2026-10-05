"""
Core data model for the Enterprise Cybersecurity Assessment Platform.

This module defines the standardized entities used across the whole platform:
Finding, Evidence, Remediation, Asset, AuditRun and the supporting enums.

Design goals
------------
* Pure standard library (no external dependencies) so the platform starts and
  runs fully offline.
* Everything is serialisable to / from plain ``dict`` (``to_dict`` /
  ``from_dict``) so findings can be stored in SQLite, DynamoDB, JSON reports or
  rendered directly in templates without conversion glue.
* Backwards compatible with the legacy auditor output
  (``{"check", "result", "severity", "recommendation"}``) via
  :func:`Finding.from_legacy`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """Finding severity. Ordered from most to least serious."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    OK = "OK"

    @property
    def weight(self) -> int:
        return {
            "CRITICAL": 40,
            "HIGH": 20,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0,
            "OK": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        """Higher rank == more serious (useful for sorting)."""
        return {
            "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
            "LOW": 2, "INFO": 1, "OK": 0,
        }[self.value]

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        """Map arbitrary/legacy severity strings onto the canonical scale."""
        if isinstance(value, Severity):
            return value
        s = str(value or "INFO").strip().upper()
        legacy = {
            "CRIT": cls.CRITICAL, "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH, "HAUT": cls.HIGH,
            "WARN": cls.MEDIUM, "WARNING": cls.MEDIUM, "MEDIUM": cls.MEDIUM,
            "MED": cls.MEDIUM, "MOYEN": cls.MEDIUM,
            "LOW": cls.LOW, "FAIBLE": cls.LOW,
            "INFO": cls.INFO, "INFORMATIONAL": cls.INFO,
            "OK": cls.OK, "PASS": cls.OK, "PASSED": cls.OK,
        }
        return legacy.get(s, cls.INFO)


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetType(str, Enum):
    WINDOWS_SERVER = "Windows Server"
    WINDOWS_CLIENT = "Windows Client"
    DOMAIN_CONTROLLER = "Domain Controller"
    LINUX = "Linux"
    NETWORK_DEVICE = "Network Device"
    CLOUD = "Cloud"
    DATABASE = "Database"
    WEB_SERVER = "Web Server"
    UNKNOWN = "Unknown"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _enum_value(v: Any) -> Any:
    return v.value if isinstance(v, Enum) else v


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """A single piece of proof supporting a finding.

    ``kind`` is a free-form label such as ``powershell``, ``registry``,
    ``ldap``, ``network_scan``, ``service``, ``event_log``, ``config`` or
    ``aws_config``. ``content`` is the raw collected artefact (command output,
    registry value, LDAP entry, scan row ...).
    """
    kind: str
    content: str
    source: str = ""            # tool / command that produced it
    host: str = ""
    collected_at: str = field(default_factory=utcnow_iso)
    audit_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
@dataclass
class Remediation:
    """Structured remediation guidance attached to a finding.

    Nothing here is executed automatically. The web / CLI layers explicitly
    require a preview + confirmation and only run allow-listed commands.
    """
    summary: str = ""
    fix_description: str = ""
    powershell: str = ""
    linux: str = ""
    config_change: str = ""
    risk_before: str = ""
    risk_after: str = ""
    rollback: str = ""
    auto_fixable: bool = False
    curated: bool = False          # True => command comes from the vetted library
    source: str = ""               # "library" | "ai" | "" (collector-provided)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Remediation":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------- #
# MITRE mapping (stored on the finding)
# --------------------------------------------------------------------------- #
@dataclass
class MitreRef:
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    sub_technique: str = ""
    confidence: str = Confidence.MEDIUM.value
    source: str = "mapping-engine"
    reference: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MitreRef":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """The standardized security finding used everywhere in the platform."""
    title: str
    description: str = ""
    severity: str = Severity.INFO.value
    category: str = "General"
    module: str = ""                       # registry module key
    # asset context
    asset: str = ""                        # hostname / label
    asset_ip: str = ""
    asset_type: str = AssetType.UNKNOWN.value
    # detection
    detection_source: str = ""
    signature: str = ""                    # stable rule key -> MITRE mapping
    confidence: str = Confidence.MEDIUM.value
    # lifecycle
    status: str = FindingStatus.OPEN.value
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)
    # risk / scoring
    risk: str = ""                         # human readable risk statement
    cve: str = ""
    cvss: Optional[float] = None
    # relationships
    mitre: List[MitreRef] = field(default_factory=list)
    compliance: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = field(default_factory=list)
    # affected principals/objects (users, computers, ports ...)
    affected: List[str] = field(default_factory=list)
    # identifiers
    id: str = ""
    audit_id: str = ""

    # ----- identity -------------------------------------------------------- #
    def compute_id(self) -> str:
        """Deterministic id from the stable parts of a finding.

        Using signature+asset+title keeps the same logical issue stable across
        audits so trends and status can be tracked.
        """
        basis = f"{self.signature}|{self.module}|{self.asset}|{self.title}"
        digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]
        return f"FND-{digest}"

    def __post_init__(self):
        self.severity = _enum_value(Severity.coerce(self.severity))
        if not self.id:
            self.id = self.compute_id()

    @property
    def severity_enum(self) -> Severity:
        return Severity.coerce(self.severity)

    # ----- serialisation --------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": _enum_value(self.severity),
            "category": self.category,
            "module": self.module,
            "asset": self.asset,
            "asset_ip": self.asset_ip,
            "asset_type": _enum_value(self.asset_type),
            "detection_source": self.detection_source,
            "signature": self.signature,
            "confidence": _enum_value(self.confidence),
            "status": _enum_value(self.status),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk": self.risk,
            "cve": self.cve,
            "cvss": self.cvss,
            "mitre": [m.to_dict() for m in self.mitre],
            "compliance": self.compliance,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "references": self.references,
            "affected": self.affected,
            "audit_id": self.audit_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        f = cls(
            title=d.get("title", "Untitled finding"),
            description=d.get("description", ""),
            severity=d.get("severity", "INFO"),
            category=d.get("category", "General"),
            module=d.get("module", ""),
            asset=d.get("asset", ""),
            asset_ip=d.get("asset_ip", ""),
            asset_type=d.get("asset_type", AssetType.UNKNOWN.value),
            detection_source=d.get("detection_source", ""),
            signature=d.get("signature", ""),
            confidence=d.get("confidence", Confidence.MEDIUM.value),
            status=d.get("status", FindingStatus.OPEN.value),
            first_seen=d.get("first_seen", utcnow_iso()),
            last_seen=d.get("last_seen", utcnow_iso()),
            risk=d.get("risk", ""),
            cve=d.get("cve", ""),
            cvss=d.get("cvss"),
            compliance=d.get("compliance", []) or [],
            references=d.get("references", []) or [],
            affected=d.get("affected", []) or [],
            id=d.get("id", ""),
            audit_id=d.get("audit_id", ""),
        )
        f.mitre = [MitreRef.from_dict(m) for m in d.get("mitre", []) or []]
        f.evidence = [Evidence.from_dict(e) for e in d.get("evidence", []) or []]
        rem = d.get("remediation")
        f.remediation = Remediation.from_dict(rem) if rem else None
        return f

    # ----- legacy bridge --------------------------------------------------- #
    @classmethod
    def from_legacy(
        cls,
        item: Dict[str, Any],
        module: str = "",
        category: str = "General",
        detection_source: str = "",
        asset: str = "",
        asset_ip: str = "",
    ) -> "Finding":
        """Build a Finding from a legacy auditor dict.

        Legacy shape: {"check", "result", "severity", "recommendation",
        optional "affected", optional "fix_command_template"}.
        """
        check = item.get("check", "Finding")
        result = item.get("result", "")
        sev = Severity.coerce(item.get("severity", "INFO"))
        affected = item.get("affected") or []
        if not affected and isinstance(result, str) and "," in result:
            # a comma separated list of principals is a common legacy pattern
            candidates = [x.strip() for x in result.split(",") if x.strip()]
            # only treat as affected list when it looks like identifiers
            if 1 < len(candidates) <= 200 and all(len(c) < 80 for c in candidates):
                affected = candidates

        remediation = None
        rec = item.get("recommendation")
        fix = item.get("fix_command_template") or item.get("command_template")
        if rec or fix:
            remediation = Remediation(
                summary=rec or "",
                fix_description=rec or "",
                powershell=fix or "",
                auto_fixable=bool(fix),
            )

        f = cls(
            title=check,
            description=str(result),
            severity=_enum_value(sev),
            category=category,
            module=module,
            detection_source=detection_source or module,
            asset=asset,
            asset_ip=asset_ip,
            affected=list(affected),
            remediation=remediation,
            # honor an explicit canonical signature, else derive from the check text
            signature=item.get("signature") or _slug(check),
        )
        if str(result):
            f.evidence.append(Evidence(
                kind="raw",
                content=str(result),
                source=detection_source or module,
                host=asset or asset_ip,
            ))
        return f


# --------------------------------------------------------------------------- #
# Asset
# --------------------------------------------------------------------------- #
@dataclass
class Asset:
    hostname: str
    ip: str = ""
    os: str = ""
    role: str = ""
    domain: str = ""
    asset_type: str = AssetType.UNKNOWN.value
    services: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    risk_score: int = 0
    last_audit: str = ""
    owner: str = ""
    tags: List[str] = field(default_factory=list)
    finding_count: int = 0
    mitre_techniques: List[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            basis = f"{self.hostname}|{self.ip}"
            self.id = "AST-" + hashlib.sha1(basis.encode()).hexdigest()[:10]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Asset":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------- #
# Audit run
# --------------------------------------------------------------------------- #
@dataclass
class AuditRun:
    audit_id: str
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = ""
    target: str = ""
    modules_used: List[str] = field(default_factory=list)
    status: str = "running"            # running | completed | failed
    summary: Dict[str, int] = field(default_factory=dict)
    security_score: int = 0
    demo: bool = False
    triggered_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditRun":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _slug(text: str) -> str:
    keep = []
    for ch in str(text).upper():
        if ch.isalnum():
            keep.append(ch)
        elif ch in " -_/":
            keep.append("_")
    slug = "".join(keep)
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug.strip("_")[:64]


def summarize(findings: List["Finding"]) -> Dict[str, int]:
    """Count findings per severity (excludes OK/INFO from the risk buckets)."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity_enum.value] = counts.get(f.severity_enum.value, 0) + 1
    counts["TOTAL"] = len(findings)
    counts["OPEN"] = sum(
        1 for f in findings
        if f.status == FindingStatus.OPEN.value and f.severity_enum.rank >= 2
    )
    counts["REMEDIATED"] = sum(
        1 for f in findings if f.status == FindingStatus.REMEDIATED.value
    )
    return counts
