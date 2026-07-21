# Security Analyst

A static code review tool: scans Python source for common vulnerability
patterns (injection, weak crypto, hardcoded secrets, insecure deserialization,
etc.), then produces both a **vulnerability report** (findings + severity)
and a **secure coding report** (why it matters + how to fix it).

Two detection layers work together:
- **Regex rules** — fast, catch obvious patterns anywhere in a line.
- **AST checks** — parse the actual Python syntax tree for higher-confidence,
  structural findings (fewer false positives than regex alone).

## Quick start

```bash
pip install -r requirements.txt --break-system-packages   # only needed for the demo

# Sanity-check the rules against the bundled vulnerable examples
python main.py demo

# Scan your own project
python main.py scan /path/to/your/project

# See past scans
python main.py history
```

Reports land in `output_reports/`. Findings also persist in `findings.db`
(SQLite) so you can track a `scan_id` over time.

## What it checks for

| Rule | Vulnerability | Severity |
|------|---------------|----------|
| HARD-001 | Hardcoded credentials | HIGH |
| CRYPTO-001 | Weak hash (MD5/SHA1) | MEDIUM |
| INJ-001 | OS command injection (os.system) | CRITICAL |
| INJ-002 | subprocess shell=True | HIGH |
| EVAL-001 | eval()/exec() on external input | CRITICAL |
| DESER-001 | Insecure deserialization (pickle) | CRITICAL |
| DESER-002 | Unsafe yaml.load | HIGH |
| SQLI-001 | SQL injection via string building | CRITICAL |
| XSS-001 | Unescaped output (mark_safe/\|safe) | MEDIUM |
| RAND-001 | Non-cryptographic RNG for security use | MEDIUM |
| DEBUG-001 | Debug mode enabled | MEDIUM |
| TLS-001 | Certificate verification disabled | HIGH |
| BIND-001 | Bound to 0.0.0.0 | LOW |
| ASSERT-001 | assert used for auth/security logic | MEDIUM |
| PATH-001 | Path traversal | MEDIUM |
| XXE-001 | XML external entity injection | HIGH |

## Project layout

```
security-analyst/
├── config.py                       # paths, ignore-dirs, severity weights
├── main.py                         # CLI: scan / demo / history
├── analyzer/
│   ├── code_scanner.py             # walks the directory, reads files
│   ├── vulnerability_detector.py   # regex + AST rule engine, Finding dataclass
│   └── secure_coding_guide.py      # per-rule fix + before/after snippet
├── reports/
│   ├── vulnerability_report.py     # findings grouped by severity (markdown)
│   └── secure_coding_report.py     # explainer + remediation (markdown)
├── database/
│   └── findings_db.py              # SQLite persistence across scans
├── educational/
│   ├── vulnerability_explainer.py  # what/why/impact per vuln class
│   └── remediation_guide.py        # category-level strategy + checklist
└── demo_app/
    └── vulnerable_examples.py      # intentionally-bad code used to test the rules
```

## Suppressing false positives

- Add `# nosec` at the end of a line to suppress findings on that exact line.
- Add `# secscan: disable-file` in the first 5 lines of a file to skip it
  entirely (useful for files whose sample/documentation text intentionally
  contains vulnerability-pattern strings, the way this project's own
  `analyzer/secure_coding_guide.py` and `educational/*.py` do).

## Running it on GitHub (no local machine needed)

`.github/workflows/security-scan.yml` runs the scanner automatically via
GitHub Actions on every push/PR to `main`, and lets you trigger it manually
from the Actions tab. Reports get uploaded as a downloadable artifact on
each run — no Colab or local Python needed. Edit the `python main.py scan .`
line if you want to point it at a subfolder instead of the whole repo.

## Notes / limitations

- This is a **static** analyzer: it flags *patterns*, not confirmed
  exploitability. Always review CRITICAL/HIGH findings manually — false
  positives are expected (e.g. `eval()` used only on hardcoded, non-user
  strings still gets flagged).
- Python-only for now (`SCANNABLE_EXTENSIONS` in `config.py`). The regex
  layer would need per-language tuning to extend to JS/PHP/etc; the AST
  layer is Python-specific by design.
- Not a replacement for dependency scanning (pip-audit, safety) — this only
  looks at first-party code you point it at.
