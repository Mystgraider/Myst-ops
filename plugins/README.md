# Bogart plugin extension points

This folder mirrors the Security Intelligence OS plan and groups future plugins
by responsibility:

- `discovery/` - DNS, HTTP, port, technology, and asset discovery plugins.
- `scanners/` - headers, auth, file, misconfiguration, and secrets scanners.
- `ai/` - explain, prioritize, recommend, and next-test intelligence plugins.
- `reports/` - PDF, HTML, JSON, SARIF, and dashboard report renderers.
- `exporters/` - integrations that publish normalized assets/findings elsewhere.
- `integrations/` - ticketing, chat, CI/CD, and external workflow integrations.
- `cloud/` - cloud asset discovery and cloud misconfiguration checks.
- `osint/` - passive OSINT enrichment plugins.
- `threat_intel/` - indicator, reputation, and threat-context enrichment.
- `enterprise/` - enterprise-only adapters such as SSO, RBAC, and audit exports.
