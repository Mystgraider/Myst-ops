"""
secure_coding_report.py
--------------------------
Renders an educational report: for every distinct rule id triggered in a
scan, show what the vulnerability is, why it matters, the category-level
remediation strategy, and a concrete before/after code fix.
"""

import os
from datetime import datetime
from typing import List

from educational.vulnerability_explainer import explain
from educational.remediation_guide import get_strategy_for_rule
from analyzer.secure_coding_guide import get_guidance

try:
    import config
except ImportError:
    class config:  # type: ignore
        REPORTS_DIR = "output_reports"


def build_report(findings: List, target_path: str, scan_id: str) -> str:
    # One entry per distinct base rule id, not one per finding
    seen_rules = {}
    for f in findings:
        base_id = f.rule_id.replace("-AST", "")
        seen_rules.setdefault(base_id, []).append(f)

    lines = []
    lines.append("# 📘 Secure Coding Report")
    lines.append("")
    lines.append(f"**Target**: `{target_path}`")
    lines.append(f"**Scan ID**: {scan_id}")
    lines.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(
        "This report explains *why* each finding matters and how to fix the "
        "underlying pattern, not just where it occurred. Use it as a learning "
        "reference alongside the raw vulnerability report."
    )
    lines.append("")

    if not seen_rules:
        lines.append("No findings to explain for this scan.")
        return "\n".join(lines)

    for base_id, occurrences in seen_rules.items():
        info = explain(base_id)
        guidance = get_guidance(base_id)
        strategy = get_strategy_for_rule(base_id)
        locations = ", ".join(f"`{f.file_path}:{f.line}`" for f in occurrences[:5])
        more = f" (+{len(occurrences) - 5} more)" if len(occurrences) > 5 else ""

        lines.append(f"## {info['name']} (`{base_id}`)")
        lines.append("")
        lines.append(f"**Found at**: {locations}{more}")
        lines.append("")
        lines.append(f"**What it is**: {info['what_it_is']}")
        lines.append("")
        if info.get("why_it_happens"):
            lines.append(f"**Why it happens**: {info['why_it_happens']}")
            lines.append("")
        lines.append(f"**Impact if exploited**: {info['impact']}")
        lines.append("")
        lines.append(f"**Fix**: {guidance['recommendation']}")
        lines.append("")
        if guidance.get("before"):
            lines.append("Before:")
            lines.append("```python")
            lines.append(guidance["before"])
            lines.append("```")
            lines.append("After:")
            lines.append("```python")
            lines.append(guidance["after"])
            lines.append("```")
        lines.append("")
        lines.append(f"**Broader strategy**: {strategy}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def save_report(findings: List, target_path: str, scan_id: str) -> str:
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    report_text = build_report(findings, target_path, scan_id)
    filename = os.path.join(config.REPORTS_DIR, f"secure_coding_report_{scan_id}.md")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"[+] Secure coding report saved: {filename}")
    return filename
