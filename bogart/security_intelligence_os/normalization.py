"""Normalization helpers for assets and findings.

The first milestone is to standardize records coming from DNS/HTTP/ports/tech
fingerprinting/cloud discovery and scanner plugins before persistence.
"""

from typing import Any, Dict, Iterable, Mapping, Optional

from .models import Asset, Evidence, Finding

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _compact_attributes(raw: Mapping[str, Any], reserved: Iterable[str]) -> Dict[str, Any]:
    reserved_set = set(reserved)
    return {key: value for key, value in raw.items() if key not in reserved_set and value is not None}


def normalize_asset(raw: Mapping[str, Any]) -> Asset:
    """Convert a discovery event into the canonical Asset shape."""
    asset_type = str(raw.get("asset_type") or raw.get("type") or "unknown").lower()
    value = str(raw.get("value") or raw.get("domain") or raw.get("ip") or raw.get("url") or "").strip()
    source = str(raw.get("source") or "unknown").strip() or "unknown"

    if not value:
        raise ValueError("asset value is required")

    return Asset(
        asset_type=asset_type,
        value=value,
        source=source,
        attributes=_compact_attributes(raw, {"asset_type", "type", "value", "domain", "ip", "url", "source"}),
    )


def normalize_finding(raw: Mapping[str, Any], asset: Optional[Asset] = None) -> Finding:
    """Convert scanner output into the canonical Finding shape."""
    normalized_asset = asset or normalize_asset(raw.get("asset", raw))
    severity = str(raw.get("severity") or "INFO").upper()
    if severity not in VALID_SEVERITIES:
        severity = "INFO"

    evidence_items = []
    for item in raw.get("evidence", []) or []:
        evidence_items.append(
            Evidence(
                evidence_type=str(item.get("evidence_type") or item.get("type") or "generic"),
                location=str(item.get("location") or item.get("path") or item.get("url") or "inline"),
                metadata=_compact_attributes(item, {"evidence_type", "type", "location", "path", "url"}),
            )
        )

    confidence = float(raw.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return Finding(
        title=str(raw.get("title") or "Untitled finding"),
        severity=severity,
        category=str(raw.get("category") or raw.get("vuln_type") or "unknown"),
        asset=normalized_asset,
        description=str(raw.get("description") or raw.get("desc") or ""),
        confidence=confidence,
        cwe=raw.get("cwe"),
        evidence=evidence_items,
        remediation=raw.get("remediation"),
        source=str(raw.get("source") or "scanner"),
        metadata=_compact_attributes(
            raw,
            {
                "title",
                "severity",
                "category",
                "vuln_type",
                "asset",
                "description",
                "desc",
                "confidence",
                "cwe",
                "evidence",
                "remediation",
                "source",
            },
        ),
    )
