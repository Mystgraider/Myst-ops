# secscan: disable-file
"""
remediation_guide.py
----------------------
Higher-level remediation strategy grouped by category, plus a general
secure-development checklist. This complements vulnerability_explainer.py
(which explains a single finding) and secure_coding_guide.py (which gives
a code-level fix) by giving process-level advice.
"""

from typing import Dict, List

CATEGORY_STRATEGIES: Dict[str, dict] = {
    "Secrets Management": dict(
        rule_ids=["HARD-001"],
        strategy=(
            "Centralize secrets outside of source control: environment variables for small "
            "projects, a dedicated secrets manager (Vault, AWS Secrets Manager, etc.) for "
            "production systems. Add a pre-commit hook or CI check (gitleaks, truffleHog) "
            "that blocks commits containing credential-shaped strings."
        ),
    ),
    "Cryptography": dict(
        rule_ids=["CRYPTO-001", "RAND-001"],
        strategy=(
            "Standardize on one vetted library per purpose: bcrypt/argon2 for password "
            "hashing, hashlib.sha256+ for integrity checks, and the 'secrets' module for "
            "anything security-relevant that needs randomness. Avoid rolling your own crypto."
        ),
    ),
    "Injection": dict(
        rule_ids=["INJ-001", "INJ-002", "EVAL-001", "SQLI-001", "PATH-001", "XXE-001"],
        strategy=(
            "The common thread across every injection class is mixing code/commands with "
            "data. Use parameterized APIs (prepared SQL statements, subprocess arg lists, "
            "safe XML parsers) so untrusted input is always treated as data, never as "
            "instructions. Validate and allowlist input at trust boundaries as defense in depth."
        ),
    ),
    "Deserialization": dict(
        rule_ids=["DESER-001", "DESER-002"],
        strategy=(
            "Prefer data-only formats (JSON) at any trust boundary. If you must deserialize "
            "richer structures, use formats/libraries designed to reject arbitrary object "
            "construction (yaml.safe_load, or signed/HMAC-verified payloads if pickle is "
            "unavoidable internally)."
        ),
    ),
    "Output Encoding / XSS": dict(
        rule_ids=["XSS-001"],
        strategy=(
            "Leave templating auto-escaping on by default. Treat every use of mark_safe/|safe "
            "as a code review flag requiring an explicit sanitization step (e.g. bleach) "
            "immediately before it."
        ),
    ),
    "Configuration & Deployment": dict(
        rule_ids=["DEBUG-001", "TLS-001", "BIND-001"],
        strategy=(
            "Separate configuration from code: drive debug flags, bind addresses, and TLS "
            "settings from environment-specific config with safe production defaults. Add a "
            "pre-deploy check that fails the build if DEBUG=True or verify=False ships to prod."
        ),
    ),
    "Authorization Logic": dict(
        rule_ids=["ASSERT-001"],
        strategy=(
            "Never rely on assert for anything that must hold true in production. Use "
            "explicit if/raise, and cover the check with a unit test that runs even when "
            "Python is invoked with -O."
        ),
    ),
}


GENERAL_CHECKLIST: List[str] = [
    "Run this scanner (or an equivalent SAST tool) in CI on every pull request, not just ad-hoc.",
    "Pair static analysis with dependency scanning (pip-audit, safety) — vulnerable libraries "
    "are just as exploitable as vulnerable first-party code.",
    "Treat every finding as a prompt to ask 'can user input reach this?' before deciding severity.",
    "Keep a secrets-scanning pre-commit hook active so credentials never reach git history.",
    "Review any CRITICAL/HIGH finding manually before shipping — automated scanners flag "
    "patterns, not confirmed exploitability; false positives are expected and normal.",
    "For anything scanner-flagged in third-party/vendor code, patch or upgrade rather than "
    "silence the finding.",
]


def get_strategy_for_rule(rule_id: str) -> str:
    base_id = rule_id.replace("-AST", "")
    for category in CATEGORY_STRATEGIES.values():
        if base_id in category["rule_ids"]:
            return category["strategy"]
    return "No category-level strategy on file for this rule id; handle case by case."


def get_all_categories() -> Dict[str, dict]:
    return CATEGORY_STRATEGIES
