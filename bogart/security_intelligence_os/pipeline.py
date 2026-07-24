"""Pipeline blueprint for the Bogart Security Intelligence OS."""

from dataclasses import dataclass, field
from typing import Dict, List

from .models import PipelineStage


@dataclass(frozen=True)
class PipelineStep:
    """A planned pipeline stage and the plugin groups expected to feed it."""

    stage: PipelineStage
    description: str
    plugin_groups: List[str] = field(default_factory=list)


def build_default_pipeline() -> List[PipelineStep]:
    """Return the initial stage order from discovery through dashboard output."""
    return [
        PipelineStep(PipelineStage.DISCOVERY, "Collect domains, APIs, cloud assets, services, and technologies.", ["discovery", "cloud", "osint"]),
        PipelineStep(PipelineStage.NORMALIZATION, "Standardize raw discovery records into canonical assets."),
        PipelineStep(PipelineStage.INVENTORY, "Persist normalized domains, IPs, APIs, technologies, services, and certificates."),
        PipelineStep(PipelineStage.SCANNING, "Run headers, auth, file, misconfiguration, and secrets checks.", ["scanners"]),
        PipelineStep(PipelineStage.FINDINGS_NORMALIZATION, "Standardize scanner findings and confidence metadata."),
        PipelineStep(PipelineStage.EVIDENCE, "Collect headers, HTML, screenshots, JSON, and HAR/log artifacts."),
        PipelineStep(PipelineStage.KNOWLEDGE_GRAPH, "Map assets, APIs, users, repositories, buckets, secrets, and relationships."),
        PipelineStep(PipelineStage.REASONING, "Correlate root cause, attack chains, business risk, and confidence score."),
        PipelineStep(PipelineStage.AI_INTELLIGENCE, "Explain, prioritize, recommend, and propose the next test.", ["ai"]),
        PipelineStep(PipelineStage.REPORTING, "Generate PDF, HTML, JSON, SARIF, and dashboard outputs.", ["reports", "exporters"]),
        PipelineStep(PipelineStage.DASHBOARD, "Expose projects, scan manager, AI service, and reporting via the user dashboard."),
    ]


def plugin_group_map() -> Dict[str, List[PipelineStage]]:
    """Map plugin folders to the pipeline stages they extend."""
    mapping: Dict[str, List[PipelineStage]] = {}
    for step in build_default_pipeline():
        for group in step.plugin_groups:
            mapping.setdefault(group, []).append(step.stage)
    mapping.setdefault("integrations", [PipelineStage.DASHBOARD, PipelineStage.REPORTING])
    mapping.setdefault("enterprise", [PipelineStage.INVENTORY, PipelineStage.REASONING, PipelineStage.REPORTING])
    mapping.setdefault("threat_intel", [PipelineStage.DISCOVERY, PipelineStage.REASONING])
    return mapping
