"""
findings_db.py
---------------
Lightweight SQLite persistence for scan findings, so results survive
between runs and you can diff scans over time (e.g. "did this PR
introduce new findings?").
"""

import sqlite3
from datetime import datetime
from typing import List, Optional

try:
    from config import DB_PATH
except ImportError:
    DB_PATH = "findings.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    conn = get_connection(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_path TEXT,
            line INTEGER,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            cwe TEXT,
            description TEXT,
            snippet TEXT,
            source TEXT,
            status TEXT DEFAULT 'OPEN',
            timestamp TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_path TEXT,
            files_scanned INTEGER,
            total_findings INTEGER,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()


def new_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_scan(scan_id: str, target_path: str, findings: List, files_scanned: int, db_path: str = DB_PATH) -> None:
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?)",
        (scan_id, target_path, files_scanned, len(findings), datetime.now().isoformat()),
    )

    for f in findings:
        cur.execute(
            """INSERT INTO findings
               (scan_id, file_path, line, rule_id, title, severity, cwe, description, snippet, source, status, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)""",
            (scan_id, f.file_path, f.line, f.rule_id, f.title, f.severity, f.cwe,
             f.description, f.snippet, f.source, datetime.now().isoformat()),
        )

    conn.commit()
    conn.close()


def get_scan_findings(scan_id: str, db_path: str = DB_PATH) -> List[dict]:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY severity", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_latest_scan_id(db_path: str = DB_PATH) -> Optional[str]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT scan_id FROM scans ORDER BY timestamp DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def get_stats(scan_id: str, db_path: str = DB_PATH) -> dict:
    conn = get_connection(db_path)
    cur = conn.cursor()
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cur.execute("SELECT severity, COUNT(*) FROM findings WHERE scan_id=? GROUP BY severity", (scan_id,))
    for severity, count in cur.fetchall():
        stats[severity] = count
    conn.close()
    return stats


def list_scans(db_path: str = DB_PATH) -> List[dict]:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
