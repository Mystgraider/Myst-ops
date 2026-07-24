# Bogart Security Intelligence OS - Phase 1 Blueprint

This document turns the architecture sketch into an implementation roadmap for
Bogart. Phase 1 is intentionally small: define stable contracts, plugin folders,
and the pipeline order before adding distributed workers or databases.

## Target architecture

1. **Discovery Engine** ingests websites, APIs/GraphQL, cloud assets, DNS,
   HTTP, ports, technologies, and asset-discovery outputs.
2. **Normalization Engine** converts each tool's raw output into canonical asset
   records.
3. **Asset Inventory Database** stores domains, IPs, APIs, technologies,
   services, and certificates.
4. **Security Scanning Engine** runs headers, authentication, files,
   misconfiguration, and secrets checks.
5. **Findings Normalization** standardizes scanner output into one finding
   schema.
6. **Evidence Collection** stores headers, HTML, screenshots, JSON, and HAR/log
   evidence.
7. **Knowledge Graph** correlates domains, APIs, JWTs, users, servers, buckets,
   repositories, and secrets.
8. **Security Reasoning Engine** derives root cause, attack chains, business
   risk, and confidence scores.
9. **AI Intelligence Engine** explains, prioritizes, recommends, and proposes
   next tests.
10. **Reporting Engine** exports PDF, HTML, JSON, SARIF, and dashboard views.
11. **User Dashboard** surfaces projects, scan management, AI service, and
   reporting.

## Phase 1 deliverables in this repo

- `bogart/security_intelligence_os/models.py` defines normalized `Asset`,
  `Finding`, `Evidence`, and `PipelineStage` contracts.
- `bogart/security_intelligence_os/normalization.py` converts raw discovery and
  scanner output into those contracts.
- `bogart/security_intelligence_os/pipeline.py` defines the first pipeline order
  and maps plugin groups to stages.
- `plugins/` contains the top-level extension points from the plan.
- `tests/test_security_intelligence_os.py` protects the new contracts.

## Next milestones

1. Wire the existing `bogart/bogart_v6.py` discovery data into
   `normalize_asset` and `normalize_finding`.
2. Add a lightweight SQLite inventory adapter before moving to PostgreSQL.
3. Create a graph-export adapter that can emit Neo4j-ready nodes/edges.
4. Add evidence storage paths for headers, HTML, JSON, screenshots, and HAR/logs.
5. Introduce a FastAPI gateway only after core contracts are stable.
