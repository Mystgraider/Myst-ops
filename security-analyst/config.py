"""
Central configuration for the Security Analyst toolkit.
Edit these values instead of hardcoding paths elsewhere.
"""

import os

# ==============================
# PATHS
# ==============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "output_reports")
DB_PATH = os.path.join(BASE_DIR, "findings.db")

os.makedirs(REPORTS_DIR, exist_ok=True)

# ==============================
# SCAN BEHAVIOR
# ==============================
# File extensions the scanner will read as source code. Python receives both
# regex and AST checks; JavaScript/TypeScript currently receive regex checks.
SCANNABLE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}

# Directories to always skip
IGNORE_DIRS = {
    ".git", "__pycache__", "venv", ".venv", "env",
    "node_modules", ".idea", ".vscode", "output_reports",
    "site-packages", "dist", "build", "coverage",
}

# Max file size to read (bytes) - avoids choking on huge/binary files
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# ==============================
# SEVERITY WEIGHTS (used for sorting + rough CVSS-style scoring)
# ==============================
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_CVSS = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}

# ==============================
# REPORT SETTINGS
# ==============================
REPORT_TITLE = "Security Analyst - Static Code Review"
INCLUDE_CODE_SNIPPETS_IN_REPORT = True
SNIPPET_CONTEXT_LINES = 1  # lines of context shown above/below the finding
