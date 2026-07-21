"""
code_scanner.py
----------------
Walks a directory tree, reads scannable source files, and runs them through
both detection layers in vulnerability_detector.py.
"""

import os
from typing import List

from analyzer.vulnerability_detector import (
    Finding,
    run_ast_checks,
    run_regex_checks,
    deduplicate,
)

try:
    import config
except ImportError:  # allow running scanner as a standalone module
    class config:  # type: ignore
        SCANNABLE_EXTENSIONS = {".py"}
        IGNORE_DIRS = {".git", "__pycache__", "venv", ".venv"}
        MAX_FILE_SIZE = 2 * 1024 * 1024


def _iter_source_files(root_path: str):
    if os.path.isfile(root_path):
        yield root_path
        return

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in config.IGNORE_DIRS]
        for fname in filenames:
            _, ext = os.path.splitext(fname)
            if ext in config.SCANNABLE_EXTENSIONS:
                yield os.path.join(dirpath, fname)


FILE_DISABLE_MARKER = "# secscan: disable-file"
LINE_SUPPRESS_MARKER = "# nosec"


def scan_file(file_path: str) -> List[Finding]:
    try:
        if os.path.getsize(file_path) > config.MAX_FILE_SIZE:
            print(f"[!] Skipping {file_path} (exceeds max file size)")
            return []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"[!] Could not read {file_path}: {e}")
        return []

    # File-level opt-out: a marker comment anywhere in the first 5 lines
    # skips the whole file. Intended for files that intentionally contain
    # vulnerability-pattern text as documentation/sample data rather than
    # real executable code (e.g. this project's own secure-coding guides).
    header = "\n".join(source.splitlines()[:5])
    if FILE_DISABLE_MARKER in header:
        return []

    findings = run_regex_checks(file_path, source) + run_ast_checks(file_path, source)
    findings = deduplicate(findings)

    # Line-level opt-out: `# nosec` on the same line suppresses that finding,
    # same convention as tools like bandit.
    lines = source.splitlines()
    findings = [
        f for f in findings
        if not (0 < f.line <= len(lines) and LINE_SUPPRESS_MARKER in lines[f.line - 1])
    ]

    return findings


def scan_path(root_path: str, verbose: bool = True) -> List[Finding]:
    """Scan a single file or an entire directory tree. Returns a flat list
    of Finding objects across all files."""
    all_findings: List[Finding] = []
    files_scanned = 0

    for file_path in _iter_source_files(root_path):
        files_scanned += 1
        findings = scan_file(file_path)
        if findings and verbose:
            print(f"[+] {file_path}: {len(findings)} finding(s)")
        all_findings.extend(findings)

    if verbose:
        print(f"\n[*] Scanned {files_scanned} file(s), {len(all_findings)} finding(s) total")

    return all_findings
