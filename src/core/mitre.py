"""
Centralized MITRE ATT&CK mapping engine.

Loads the curated ATT&CK catalog (``data/mitre_attack.json``) and the mapping
configuration (``data/mitre_mappings.json``) and enriches findings with the
techniques they technically support.

The mapping is *config driven*: audit modules never assign technique IDs
themselves. To add or refine a mapping, edit ``data/mitre_mappings.json`` — no
module code changes are required.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

from .models import Finding, MitreRef, Severity

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@lru_cache(maxsize=1)
def _load_catalog() -> Dict[str, Any]:
    with open(os.path.join(_DATA_DIR, "mitre_attack.json"), encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _load_mappings() -> Dict[str, Any]:
    with open(os.path.join(_DATA_DIR, "mitre_mappings.json"), encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _technique_index() -> Dict[str, Dict[str, Any]]:
    return {t["id"]: t for t in _load_catalog().get("techniques", [])}


@lru_cache(maxsize=1)
def _tactic_index() -> Dict[str, Dict[str, Any]]:
    return {t["name"]: t for t in _load_catalog().get("tactics", [])}


class MitreEngine:
    """Resolve findings to ATT&CK techniques and expose matrix aggregation."""

    def __init__(self) -> None:
        self.catalog = _load_catalog()
        self.mappings = _load_mappings()
        self.techniques = _technique_index()
        self.tactics = _tactic_index()

    # ------------------------------------------------------------------ #
    # technique / tactic lookup
    # ------------------------------------------------------------------ #
    def technique(self, tid: str) -> Optional[Dict[str, Any]]:
        return self.techniques.get(tid)

    def technique_name(self, tid: str) -> str:
        t = self.techniques.get(tid)
        return t["name"] if t else tid

    def technique_tactic(self, tid: str) -> str:
        t = self.techniques.get(tid)
        return t.get("tactic", "") if t else ""

    def build_ref(self, tid: str, confidence: str, rationale: str,
                  source: str = "mapping-engine") -> Optional[MitreRef]:
        t = self.techniques.get(tid)
        if not t:
            return None
        parent = t.get("parent")
        sub = ""
        name = t["name"]
        if parent:
            # sub-technique: split "Parent: Sub" name when present
            sub = name.split(":", 1)[-1].strip() if ":" in name else name
        return MitreRef(
            technique_id=tid,
            technique_name=name,
            tactic=t.get("tactic", ""),
            sub_technique=sub,
            confidence=confidence,
            source=source,
            reference=t.get("url", ""),
            rationale=rationale,
        )

    # ------------------------------------------------------------------ #
    # mapping
    # ------------------------------------------------------------------ #
    # signature suffixes for operational/diagnostic findings that are NOT
    # security weaknesses and must never receive ATT&CK techniques
    _OPERATIONAL_SUFFIX = ("_UNREACHABLE", "_UNAVAILABLE", "_ERROR")

    def map_finding(self, finding: Finding) -> List[MitreRef]:
        """Return the list of MitreRefs a finding technically supports."""
        # never map non-issues
        if finding.severity_enum in (Severity.OK,):
            return []
        # never map collector/connectivity diagnostics
        sig = (finding.signature or "").upper()
        if sig.endswith(self._OPERATIONAL_SUFFIX) or finding.module == "collector_diagnostics":
            return []

        refs: Dict[str, MitreRef] = {}

        # (1) exact canonical signature
        sig = (finding.signature or "").upper()
        for tech in self.mappings.get("signatures", {}).get(sig, []):
            ref = self.build_ref(tech["id"], tech.get("confidence", "medium"),
                                 tech.get("rationale", ""), source="signature")
            if ref:
                refs[ref.technique_id] = ref

        # (2) keyword patterns
        haystack = " ".join([
            finding.title or "",
            finding.signature or "",
            finding.module or "",
            finding.category or "",
            finding.description or "",
        ]).lower()

        for pat in self.mappings.get("patterns", []):
            anys = [k.lower() for k in pat.get("any", [])]
            nots = [k.lower() for k in pat.get("not", [])]
            if anys and not any(k in haystack for k in anys):
                continue
            if nots and any(k in haystack for k in nots):
                continue
            for tech in pat.get("techniques", []):
                # keep the highest-confidence variant if seen twice
                ref = self.build_ref(tech["id"], tech.get("confidence", "medium"),
                                     tech.get("rationale", ""), source="pattern")
                if not ref:
                    continue
                existing = refs.get(ref.technique_id)
                if existing is None or _conf_rank(ref.confidence) > _conf_rank(existing.confidence):
                    refs[ref.technique_id] = ref

        return list(refs.values())

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        """Attach MITRE refs to each finding in place and return the list."""
        for f in findings:
            mapped = self.map_finding(f)
            if mapped:
                f.mitre = mapped
        return findings

    # ------------------------------------------------------------------ #
    # matrix / coverage aggregation
    # ------------------------------------------------------------------ #
    def coverage(self, findings: List[Finding]) -> Dict[str, Any]:
        """Aggregate observed techniques/tactics for the ATT&CK matrix view."""
        observed: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            for ref in f.mitre:
                entry = observed.setdefault(ref.technique_id, {
                    "id": ref.technique_id,
                    "name": ref.technique_name,
                    "tactic": ref.tactic,
                    "findings": 0,
                    "max_severity": Severity.INFO.value,
                    "assets": set(),
                })
                entry["findings"] += 1
                if f.asset:
                    entry["assets"].add(f.asset)
                if f.severity_enum.rank > Severity.coerce(entry["max_severity"]).rank:
                    entry["max_severity"] = f.severity_enum.value

        for e in observed.values():
            e["assets"] = sorted(e["assets"])
            e["asset_count"] = len(e["assets"])

        total_techniques = len(self.techniques)
        tactics_out = []
        for tactic in self.catalog.get("tactics", []):
            tname = tactic["name"]
            tech_in_tactic = [
                t for t in self.techniques.values() if t.get("tactic") == tname
            ]
            observed_in_tactic = [
                e for e in observed.values() if e["tactic"] == tname
            ]
            max_sev = Severity.INFO.value
            for e in observed_in_tactic:
                if Severity.coerce(e["max_severity"]).rank > Severity.coerce(max_sev).rank:
                    max_sev = e["max_severity"]
            tactics_out.append({
                "id": tactic["id"],
                "name": tname,
                "short": tactic.get("short", ""),
                "technique_count": len(tech_in_tactic),
                "observed_count": len(observed_in_tactic),
                "finding_count": sum(e["findings"] for e in observed_in_tactic),
                "max_severity": max_sev,
                "techniques": sorted(
                    [
                        {
                            "id": t["id"],
                            "name": t["name"],
                            "observed": t["id"] in observed,
                            "findings": observed.get(t["id"], {}).get("findings", 0),
                            "max_severity": observed.get(t["id"], {}).get("max_severity", ""),
                        }
                        for t in tech_in_tactic
                    ],
                    key=lambda x: (not x["observed"], x["id"]),
                ),
            })

        observed_ids = set(observed.keys())
        return {
            "tactics": tactics_out,
            "observed_techniques": sorted(observed.values(),
                                          key=lambda e: (-e["findings"], e["id"])),
            "observed_count": len(observed_ids),
            "total_techniques": total_techniques,
            "coverage_pct": round(100.0 * len(observed_ids) / total_techniques, 1)
            if total_techniques else 0.0,
            "tactic_count": len(self.catalog.get("tactics", [])),
        }


def _conf_rank(c: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(str(c).lower(), 0)


# module-level singleton
_ENGINE: Optional[MitreEngine] = None


def get_engine() -> MitreEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = MitreEngine()
    return _ENGINE
