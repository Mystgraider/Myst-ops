"""Shared data contracts for Bogart's security-intelligence pipeline.

These dataclasses are intentionally small and dependency-free. They define the
normalized shape each future subsystem should exchange before heavier storage
(PostgreSQL/Neo4j/Redis/object storage) is introduced.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    """Return a stable UTC timestamp for normalized records."""
    return datetime.now(timezone.utc).isoformat()


class PipelineStage(str, Enum):
    """Top-level stages from the Security Intelligence OS architecture."""

    DISCOVERY = "discovery"
    NORMALIZATION = "normalization"
    INVENTORY = "inventory"
    SCANNING = "scanning"
    FINDINGS_NORMALIZATION = "findings_normalization"
    EVIDENCE = "evidence"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    REASONING = "reasoning"
    AI_INTELLIGENCE = "ai_intelligence"
    REPORTING = "reporting"
    DASHBOARD = "dashboard"


@dataclass(frozen=True)
class Asset:
    """Normalized inventory item discovered from internet/cloud/API sources."""

    asset_type: str
    value: str
    source: str
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """Evidence attached to a finding or graph relationship."""

    evidence_type: str
    location: str
    captured_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """Normalized vulnerability/risk finding produced by scanners."""

    title: str
    severity: str
    category: str
    asset: Asset
    description: str
    confidence: float = 0.5
    cwe: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
    source: str = "scanner"
    discovered_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)
