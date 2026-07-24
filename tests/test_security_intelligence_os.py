import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from bogart.security_intelligence_os import normalize_asset, normalize_finding
from bogart.security_intelligence_os.models import PipelineStage
from bogart.security_intelligence_os.pipeline import build_default_pipeline, plugin_group_map


class SecurityIntelligenceOSTests(unittest.TestCase):
    def test_normalize_asset_accepts_discovery_records(self):
        asset = normalize_asset({"domain": "api.example.com", "source": "dns", "status": 200})

        self.assertEqual(asset.asset_type, "domain")
        self.assertEqual(asset.value, "api.example.com")
        self.assertEqual(asset.source, "dns")
        self.assertEqual(asset.attributes["status"], 200)

    def test_normalize_asset_infers_common_asset_types(self):
        self.assertEqual(normalize_asset({"ip": "192.0.2.10"}).asset_type, "ip")
        self.assertEqual(normalize_asset({"url": "https://api.example.com/v1"}).asset_type, "url")
        self.assertEqual(normalize_asset({"value": "cdn.example.com"}).asset_type, "domain")

    def test_normalize_finding_clamps_confidence_and_evidence(self):
        finding = normalize_finding(
            {
                "title": "Missing CSP",
                "severity": "high",
                "category": "headers",
                "asset": {"url": "https://example.com", "type": "website", "source": "http"},
                "desc": "Content-Security-Policy header is absent.",
                "confidence": 2,
                "evidence": [{"type": "headers", "location": "https://example.com"}],
            }
        )

        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.confidence, 1.0)
        self.assertEqual(finding.asset.asset_type, "website")
        self.assertEqual(finding.evidence[0].evidence_type, "headers")

    def test_normalize_finding_handles_bad_confidence_and_evidence_items(self):
        finding = normalize_finding(
            {
                "title": "Weak signal",
                "severity": "unexpected",
                "domain": "example.com",
                "confidence": "not-a-number",
                "evidence": ["raw-string-evidence"],
            }
        )

        self.assertEqual(finding.severity, "INFO")
        self.assertEqual(finding.confidence, 0.5)
        self.assertEqual(finding.evidence[0].evidence_type, "generic")

    def test_default_pipeline_order_matches_architecture(self):
        stages = [step.stage for step in build_default_pipeline()]

        self.assertEqual(stages[0], PipelineStage.DISCOVERY)
        self.assertEqual(stages[-1], PipelineStage.DASHBOARD)
        self.assertIn(PipelineStage.KNOWLEDGE_GRAPH, stages)
        self.assertIn(PipelineStage.AI_INTELLIGENCE, stages)

    def test_plugin_group_map_exposes_requested_extension_points(self):
        mapping = plugin_group_map()

        for group in ["discovery", "scanners", "ai", "reports", "cloud", "osint", "threat_intel", "enterprise"]:
            self.assertIn(group, mapping)


if __name__ == "__main__":
    unittest.main()
