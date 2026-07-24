"""Normalization helpers for assets and findings.

The first milestone is to standardize records coming from DNS/HTTP/ports/tech
fingerprinting/cloud discovery and scanner plugins before persistence.
"""

import ipaddress
from typing import Any, Dict, Iterable, Mapping, Optional
from urllib.parse import urlparse

from .models import Asset, Evidence, Finding

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _compact_attributes(raw: Mapping[str, Any], reserved: Iterable[str]) -> Dict[str, Any]:
    reserved_set = set(reserved)
    return {key: value for key, value in raw.items() if key not in reserved_set and value is not None}


def _coerce_mapping(value: Any, fallback: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return value when it is mapping-like, otherwise use a safe fallback."""
    return value if isinstance(value, Mapping) else fallback


def _infer_asset_type(raw: Mapping[str, Any], value: str) -> str:
    explicit_type = raw.get("asset_type") or raw.get("type")
    if explicit_type:
        return str(explicit_type).lower()
    if raw.get("domain"):
        return "domain"
    if raw.get("ip"):
        return "ip"
    if raw.get("url"):
        return "url"

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return "url"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if "." in value and " " not in value:
        return "domain"
    return "unknown"


def normalize_asset(raw: Mapping[str, Any]) -> Asset:
    """Convert a discovery event into the canonical Asset shape."""
    value = str(raw.get("value") or raw.get("domain") or raw.get("ip") or raw.get("url") or "").strip()
    source = str(raw.get("source") or "unknown").strip() or "unknown"

    if not value:
        raise ValueError("asset value is required")

    return Asset(
        asset_type=_infer_asset_type(raw, value),
        value=value,
        source=source,
        attributes=_compact_attributes(raw, {"asset_type", "type", "value", "domain", "ip", "url", "source"}),
    )


def _normalize_confidence(raw_value: Any) -> float:
    try:
        confidence = float(raw_value)
    except (TypeError, ValueError):
        confidence = 0.5
    return max(0.0, min(1.0, confidence))


def normalize_finding(raw: Mapping[str, Any], asset: Optional[Asset] = None) -> Finding:
    """Convert scanner output into the canonical Finding shape."""
    asset_payload = _coerce_mapping(raw.get("asset"), raw)
    normalized_asset = asset or normalize_asset(asset_payload)
    severity = str(raw.get("severity") or "INFO").upper()
    if severity not in VALID_SEVERITIES:
        severity = "INFO"

    evidence_items = []
    for item in raw.get("evidence", []) or []:
        evidence = _coerce_mapping(item, {})
        evidence_items.append(
            Evidence(
                evidence_type=str(evidence.get("evidence_type") or evidence.get("type") or "generic"),
                location=str(evidence.get("location") or evidence.get("path") or evidence.get("url") or "inline"),
                metadata=_compact_attributes(evidence, {"evidence_type", "type", "location", "path", "url"}),
            )
        )

    return Finding(
        title=str(raw.get("title") or "Untitled finding"),
        severity=severity,
        category=str(raw.get("category") or raw.get("vuln_type") or "unknown"),
        asset=normalized_asset,
        description=str(raw.get("description") or raw.get("desc") or ""),
        confidence=_normalize_confidence(raw.get("confidence", 0.5)),
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
