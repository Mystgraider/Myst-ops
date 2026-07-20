#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BOGART v6 - Ultimate Bug Bounty Recon & Assessment System
✅ Production-Ready | ✅ Resumable | ✅ Scope-Aware | ✅ Evidence-Centric
Author: Security Researcher (Educational Use Only)
⚠️ WARNING: For authorized security testing ONLY. Do NOT use without explicit permission.
"""

import os
import sys
import json
import time
import shutil
import asyncio
import sqlite3
import hashlib
import subprocess
import requests
import re
import fnmatch
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

# ==============================
# CONFIGURATION (SET BEFORE RUN)
# ==============================
# Each of these can still be edited directly for Colab use (unchanged
# behavior), or overridden via environment variables - which is what the
# GitHub Actions workflow uses so you don't have to edit this file per scan.
TARGET_DOMAIN = os.getenv("BOGART_TARGET_DOMAIN", "example.com")            # ← CHANGE THIS
PROGRAM_NAME = os.getenv("BOGART_PROGRAM_NAME", "Example Bug Bounty")       # ← CHANGE THIS
_scope_env = os.getenv("BOGART_SCOPE_ALLOWLIST", "")
SCOPE_ALLOWLIST = [s.strip() for s in _scope_env.split(",") if s.strip()] if _scope_env \
    else ["*.example.com", "example.com"]                                  # ← MUST BE SET
ENABLE_HEAVY_TOOLS = os.getenv("BOGART_ENABLE_HEAVY_TOOLS", "true").lower() != "false"  # Set False for Colab
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# ==============================
# CORE UTILITIES
# ==============================
def is_in_scope(url: str) -> bool:
    """Strict scope validation using allowlist"""
    if not SCOPE_ALLOWLIST:
        print("[!] ERROR: SCOPE_ALLOWLIST is empty. Blocking all requests.")
        return False
    
    parsed = urlparse(url)
    domain = parsed.netloc or url
    if not domain:
        return False
    
    for pattern in SCOPE_ALLOWLIST:
        if fnmatch.fnmatch(domain, pattern):
            return True
    return False

def safe_request(url: str, method: str = "GET", headers: dict = None, timeout: int = 15) -> Optional[dict]:
    """Safe HTTP request with scope check and retry"""
    if not is_in_scope(url):
        return None
    
    if headers is None:
        headers = {"User-Agent": "BOGART-v6/1.0"}
    
    for attempt in range(3):
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text[:10000],
                "full_text": resp.text if ENABLE_HEAVY_TOOLS else None
            }
        except Exception as e:
            time.sleep(2 ** attempt)
    return None

def send_telegram(msg: str):
    if TG_BOT_TOKEN and TG_CHAT_ID:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=5
            )
        except:
            pass

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

# ==============================
# DATABASE SETUP
# ==============================
DB_PATH = "bogart.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    
    tables = [
        ("subdomains", "domain TEXT UNIQUE, first_seen TEXT, last_seen TEXT, status TEXT, source TEXT"),
        ("resolved_hosts", "domain TEXT UNIQUE, ip TEXT, is_alive INTEGER, http_status INTEGER, title TEXT, tech TEXT, last_checked TEXT"),
        ("findings", "id INTEGER PRIMARY KEY, domain TEXT, url TEXT, vuln_type TEXT, severity TEXT, cvss REAL, title TEXT, desc TEXT, evidence TEXT, request TEXT, response TEXT, status TEXT, timestamp TEXT"),
        ("js_endpoints", "url TEXT, endpoint TEXT, method TEXT, timestamp TEXT, UNIQUE(url, endpoint)"),
        ("parameters", "url TEXT, param TEXT, type TEXT, source TEXT, timestamp TEXT, UNIQUE(url, param)"),
        ("scan_logs", "step TEXT, status TEXT, timestamp TEXT"),
        ("evidence", "finding_id INTEGER, type TEXT, path TEXT, timestamp TEXT")
    ]
    
    for name, schema in tables:
        cursor.execute(f"CREATE TABLE IF NOT EXISTS {name} ({schema})")
    
    conn.commit()
    return conn

def mark_step(step: str, status: str = "COMPLETED"):
    conn = init_db()
    conn.cursor().execute("INSERT INTO scan_logs VALUES (?, ?, ?)", (step, status, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_completed_steps() -> Set[str]:
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("SELECT step FROM scan_logs WHERE status='COMPLETED'")
    steps = {row[0] for row in cursor.fetchall()}
    conn.close()
    return steps

# ==============================
# RECON MODULES
# ==============================
def enumerate_subdomains() -> List[str]:
    subs = set()
    
    # 1. crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{TARGET_DOMAIN}&output=json"
        data = safe_request(url)
        if data and data["status"] == 200:
            for entry in json.loads(data["text"]):
                names = entry.get("name_value", "").split("\n")
                for n in names:
                    sub = n.replace("*.", "").strip()
                    if sub and is_in_scope(sub):
                        subs.add(sub)
    except: pass
    
    # 2. waybackurls (if available)
    try:
        result = subprocess.run(["waybackurls", TARGET_DOMAIN], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("http"):
                    parsed = urlparse(line)
                    if parsed.netloc and is_in_scope(parsed.netloc):
                        subs.add(parsed.netloc)
    except: pass

    # 3. subfinder (if available) - aggregates many passive sources in one pass
    try:
        result = subprocess.run(
            ["subfinder", "-d", TARGET_DOMAIN, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                sub = line.strip()
                if sub and is_in_scope(sub):
                    subs.add(sub)
    except: pass

    # 4. gau (if available) - GetAllUrls: Wayback + OTX + CommonCrawl, broader than waybackurls alone
    try:
        result = subprocess.run(["gau", TARGET_DOMAIN], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("http"):
                    parsed = urlparse(line)
                    if parsed.netloc and is_in_scope(parsed.netloc):
                        subs.add(parsed.netloc)
    except: pass
    
    # Save to DB
    conn = init_db()
    now = datetime.now().isoformat()
    for sub in subs:
        conn.cursor().execute(
            "INSERT OR REPLACE INTO subdomains VALUES (?, ?, ?, ?, ?)",
            (sub, now, now, "DISCOVERED", "comprehensive")
        )
    conn.commit()
    conn.close()
    
    print(f"[+] Found {len(subs)} subdomains in scope")
    return list(subs)

def resolve_hosts(subdomains: List[str]) -> List[str]:
    alive = []
    
    # Use massdns if available, else fallback to dnspython
    try:
        with open("/tmp/subs.txt", "w") as f:
            f.write("\n".join(subdomains))
        
        result = subprocess.run([
            "massdns", "-r", "/usr/share/massdns/lists/resolvers.txt",
            "-t", "A", "-o", "S", "-q", "/tmp/subs.txt"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if " A " in line:
                    parts = line.split()
                    domain, ip = parts[0].rstrip('.'), parts[2]
                    if is_in_scope(domain):
                        alive.append(domain)
                        conn = init_db()
                        conn.cursor().execute(
                            "INSERT OR REPLACE INTO resolved_hosts VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (domain, ip, 1, 0, "", "", datetime.now().isoformat())
                        )
                        conn.commit()
                        conn.close()
    except:
        # Fallback: simple DNS resolve
        import dns.resolver
        for sub in subdomains:
            try:
                answers = dns.resolver.resolve(sub, 'A')
                for rdata in answers:
                    if is_in_scope(sub):
                        alive.append(sub)
                        conn = init_db()
                        conn.cursor().execute(
                            "INSERT OR REPLACE INTO resolved_hosts VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (sub, str(rdata.address), 1, 0, "", "", datetime.now().isoformat())
                        )
                        conn.commit()
                        conn.close()
                        break
            except: pass
    
    print(f"[+] {len(alive)} hosts resolved and alive")
    return alive

def probe_http(hosts: List[str]) -> List[str]:
    alive_urls = []

    # Preferred path: httpx (ProjectDiscovery) - single fast pass that also
    # gives us title + tech detection for free instead of a second request.
    if shutil.which("httpx"):
        try:
            with open("/tmp/probe_hosts.txt", "w") as f:
                f.write("\n".join(hosts))

            result = subprocess.run(
                ["httpx", "-l", "/tmp/probe_hosts.txt", "-json", "-silent",
                 "-title", "-tech-detect", "-status-code"],
                capture_output=True, text=True, timeout=300
            )
            conn = init_db()
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = j.get("input", j.get("host", ""))
                url = j.get("url", f"https://{host}")
                status = j.get("status_code", 0)
                if not is_in_scope(url) or status not in (200, 301, 302, 401, 403):
                    continue
                alive_urls.append(url)
                tech = ",".join(j.get("tech", [])) if j.get("tech") else "Unknown"
                conn.cursor().execute(
                    "UPDATE resolved_hosts SET is_alive=1, http_status=?, title=?, tech=?, last_checked=? WHERE domain=?",
                    (status, j.get("title", ""), tech, datetime.now().isoformat(), host)
                )
            conn.commit()
            conn.close()

            if alive_urls:
                print(f"[+] {len(alive_urls)} HTTP hosts confirmed alive (via httpx)")
                return alive_urls
            # if httpx ran but found nothing, fall through to manual probing
            # in case of a parsing mismatch rather than assuming zero hosts
        except Exception as e:
            print(f"[!] httpx probe failed, falling back to manual probing: {e}")

    # Fallback: manual per-host request (no external tool required)
    for host in hosts:
        url = f"https://{host}"
        data = safe_request(url)
        if data and data["status"] in [200, 301, 302, 401, 403]:
            alive_urls.append(url)
            title_match = re.search(r'<title>(.*?)</title>', data["text"], re.I)
            title = title_match.group(1) if title_match else ""
            conn = init_db()
            conn.cursor().execute(
                "UPDATE resolved_hosts SET is_alive=1, http_status=?, title=?, tech=?, last_checked=? WHERE domain=?",
                (data["status"], 
                 title,
                 "Unknown",
                 datetime.now().isoformat(),
                 host)
            )
            conn.commit()
            conn.close()
    
    print(f"[+] {len(alive_urls)} HTTP hosts confirmed alive")
    return alive_urls

# ==============================
# SCANNING MODULES
# ==============================
def update_nuclei_templates():
    """Keep nuclei's PoC coverage current. Best-effort; skip silently if nuclei isn't installed."""
    if not shutil.which("nuclei"):
        return
    try:
        subprocess.run(["nuclei", "-update-templates"], capture_output=True, text=True, timeout=300)
        print("[+] nuclei templates updated")
    except Exception as e:
        print(f"[!] nuclei template update skipped: {e}")


def run_afrog(urls: List[str]):
    """Second active scanner alongside nuclei - different, independently maintained
    PoC set, so it catches things nuclei's template library doesn't cover (and vice versa)."""
    if not ENABLE_HEAVY_TOOLS or not shutil.which("afrog"):
        return

    print("[*] Running afrog...")
    result_path = "/tmp/afrog_result.json"
    try:
        with open("/tmp/afrog_targets.txt", "w") as f:
            f.write("\n".join(urls))

        # remove any stale result file so a failed run isn't mistaken for old data
        if os.path.exists(result_path):
            os.remove(result_path)

        subprocess.run([
            "afrog", "-T", "/tmp/afrog_targets.txt",
            "-S", "low,medium,high,critical",
            "-json", result_path,
            "-silent"
        ], capture_output=True, text=True, timeout=1800)

        if not os.path.exists(result_path):
            print("[*] afrog produced no result file (no findings, or the scan failed)")
            return

        with open(result_path) as f:
            raw = f.read().strip()
        if not raw:
            return
        # afrog writes results as a JSON array and only closes it when the scan
        # completes cleanly - guard against a truncated file just in case.
        if not raw.endswith("]"):
            raw = raw.rstrip(",\n") + "]"

        try:
            afrog_findings = json.loads(raw)
        except json.JSONDecodeError:
            print("[!] afrog result file was not valid JSON, skipping")
            return

        conn = init_db()
        for j in afrog_findings:
            url = j.get("fulltarget") or j.get("target", "")
            poc_id = j.get("id", "")
            info = j.get("info", {})
            severity = info.get("severity", "unknown").upper()
            name = info.get("name", "")
            desc = info.get("description", "")

            if is_in_scope(url):
                cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity, 0.0)
                conn.cursor().execute(
                    "INSERT INTO findings (domain, url, vuln_type, severity, cvss, title, desc, evidence, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (url, url, f"Afrog:{poc_id}", severity, cvss, name, desc, "", "OPEN", datetime.now().isoformat())
                )
        conn.commit()
        conn.close()
        print(f"[+] afrog found {len(afrog_findings)} result(s)")
    except Exception as e:
        print(f"[-] afrog failed: {e}")


def run_nuclei(urls: List[str]):
    if not ENABLE_HEAVY_TOOLS:
        return
    
    print("[*] Running nuclei...")
    try:
        with open("/tmp/targets.txt", "w") as f:
            f.write("\n".join(urls))
        
        result = subprocess.run([
            "nuclei", "-l", "/tmp/targets.txt",
            "-severity", "low,medium,high,critical",
            "-json", "-silent", "-rate-limit", "10"
        ], capture_output=True, text=True, timeout=1800)
        
        if result.returncode in [0, 1]:
            conn = init_db()
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        j = json.loads(line)
                        template_id = j.get("template-id", "")
                        url = j.get("matched-at", "")
                        severity = j.get("info", {}).get("severity", "unknown").upper()
                        name = j.get("info", {}).get("name", "")
                        desc = j.get("info", {}).get("description", "")
                        evidence = j.get("matched-line", "")
                        
                        if is_in_scope(url):
                            cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity, 0.0)
                            
                            conn.cursor().execute(
                                "INSERT INTO findings (domain, url, vuln_type, severity, cvss, title, desc, evidence, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (url, url, f"Nuclei:{template_id}", severity, cvss, name, desc, evidence, "OPEN", datetime.now().isoformat())
                            )
                    except: pass
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[-] nuclei failed: {e}")

def discover_parameters(urls: List[str]):
    if not ENABLE_HEAVY_TOOLS:
        return
    
    print("[*] Running arjun...")
    try:
        with open("/tmp/arjun_targets.txt", "w") as f:
            f.write("\n".join(urls))
        
        result = subprocess.run([
            "arjun", "-i", "/tmp/arjun_targets.txt",
            "-oJ", "/tmp/arjun.json", "-t", "5"
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            with open("/tmp/arjun.json") as f:
                data = json.load(f)
            
            conn = init_db()
            for url, params in data.items():
                if is_in_scope(url):
                    for p in params:
                        conn.cursor().execute(
                            "INSERT OR IGNORE INTO parameters VALUES (?, ?, ?, ?, ?)",
                            (url, p.get("param", ""), p.get("type", "unknown"), "arjun", datetime.now().isoformat())
                        )
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[-] arjun failed: {e}")

def crawl_endpoints(urls: List[str]) -> List[str]:
    """Use katana (if available) to crawl each alive host and discover real
    JS files and endpoints, instead of guessing a single /main.js path."""
    discovered = []
    if not shutil.which("katana"):
        return discovered

    try:
        with open("/tmp/katana_targets.txt", "w") as f:
            f.write("\n".join(urls))

        result = subprocess.run(
            ["katana", "-list", "/tmp/katana_targets.txt", "-silent",
             "-jc", "-d", "2", "-timeout", "10"],
            capture_output=True, text=True, timeout=600
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http") and is_in_scope(line):
                discovered.append(line)
    except Exception as e:
        print(f"[!] katana crawl failed: {e}")

    print(f"[+] katana discovered {len(discovered)} URLs")
    return discovered


def scan_js(urls: List[str]):
    print("[*] Scanning JS files...")
    js_patterns = [
        r'["\'](/api/[a-zA-Z0-9_\-./]+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']'
    ]

    # Prefer real JS files found by katana's crawl; fall back to the old
    # guessed /main.js path per host if katana isn't installed or found none.
    crawled = crawl_endpoints(urls)
    js_urls = [u for u in crawled if u.split("?")[0].endswith(".js")]
    if not js_urls:
        js_urls = [u.rstrip("/") + "/main.js" for u in urls[:20]]

    conn = init_db()
    for js_url in js_urls[:50]:  # cap for speed
        data = safe_request(js_url)
        if data and data["status"] == 200:
            text = data["text"]
            for pattern in js_patterns:
                matches = re.findall(pattern, text)
                for ep in matches:
                    conn.cursor().execute(
                        "INSERT OR IGNORE INTO js_endpoints VALUES (?, ?, ?, ?)",
                        (js_url, ep, "GET", datetime.now().isoformat())
                    )
    conn.commit()
    conn.close()

def check_takeover(subdomains: List[str]):
    takeover_signatures = {
        "github.io": "There isn't a GitHub Pages site here",
        "herokuapp.com": "No such app",
        "azurewebsites.net": "404 Web Site not found"
    }
    
    conn = init_db()
    for sub in subdomains:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(sub, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).lower()
                for provider, sig in takeover_signatures.items():
                    if provider in cname:
                        print(f"[!] Takeover: {sub} -> {cname}")
                        conn.cursor().execute(
                            "INSERT INTO findings (domain, url, vuln_type, severity, cvss, title, desc, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (sub, f"https://{sub}", "Subdomain Takeover", "HIGH", 7.5,
                             f"Potential {provider} Takeover", f"CNAME points to {cname}", "OPEN", datetime.now().isoformat())
                        )
        except: pass
    conn.commit()
    conn.close()

# ==============================
# REPORTING
# ==============================
def generate_report():
    conn = init_db()
    cursor = conn.cursor()
    
    # Stats
    cursor.execute("SELECT COUNT(*) FROM subdomains")
    total_subs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM resolved_hosts WHERE is_alive=1")
    alive_hosts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM findings")
    total_findings = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'")
    critical = cursor.fetchone()[0]
    
    # Report content
    report = f"""# 🛡️ BOGART v6 Security Report
**Target**: {TARGET_DOMAIN}
**Program**: {PROGRAM_NAME}
**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Scan Mode**: Comprehensive

## Summary
- Subdomains: {total_subs}
- Alive Hosts: {alive_hosts}
- Findings: {total_findings}
  - Critical: {critical}

## Findings
"""
    
    cursor.execute("SELECT * FROM findings ORDER BY cvss DESC")
    for row in cursor.fetchall():
        _, domain, url, vuln_type, severity, cvss, title, desc, _, _, status, ts = row
        report += f"""### {title}
- **Severity**: {severity} (CVSS: {cvss})
- **URL**: `{url}`
- **Type**: {vuln_type}
- **Description**: {desc}
- **Status**: {status}
- **Time**: {ts[:19]}
\n"""
    
    conn.close()
    
    filename = f"BOGART_REPORT_{TARGET_DOMAIN.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"[+] Report saved: {filename}")
    return filename, total_findings

# ==============================
# MAIN EXECUTION PIPELINE
# ==============================
async def main():
    print("=" * 70)
    print("🛡️  BOGART v6 - Ultimate Bug Bounty Recon & Assessment System")
    print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 70)
    
    # Validate scope
    if not SCOPE_ALLOWLIST:
        print("[!] ERROR: SCOPE_ALLOWLIST is empty. Exiting.")
        sys.exit(1)
    
    # Initialize DB
    init_db()
    completed = get_completed_steps()
    
    # Phase 1: Passive Recon
    if "passive_recon" not in completed:
        print("\n[1/6] Passive Reconnaissance")
        subs = enumerate_subdomains()
        mark_step("passive_recon")
    else:
        print("\n[1/6] Skipping: passive_recon (completed)")
        conn = init_db()
        subs = [row[0] for row in conn.cursor().execute("SELECT domain FROM subdomains").fetchall()]
        conn.close()
    
    # Phase 2: DNS Resolution
    if "dns_resolve" not in completed:
        print("\n[2/6] DNS Resolution")
        alive_hosts = resolve_hosts(subs)
        mark_step("dns_resolve")
    else:
        print("\n[2/6] Skipping: dns_resolve (completed)")
        conn = init_db()
        alive_hosts = [row[0] for row in conn.cursor().execute("SELECT domain FROM resolved_hosts WHERE is_alive=1").fetchall()]
        conn.close()
    
    # Phase 3: HTTP Probing
    if "http_probe" not in completed:
        print("\n[3/6] HTTP Probing")
        alive_urls = probe_http(alive_hosts)
        mark_step("http_probe")
    else:
        print("\n[3/6] Skipping: http_probe (completed)")
        conn = init_db()
        alive_urls = [f"https://{row[0]}" for row in conn.cursor().execute(
            "SELECT domain FROM resolved_hosts WHERE is_alive=1 AND http_status IN (200,301,302,401,403)"
        ).fetchall()]
        conn.close()
    
    # Phase 4: Vulnerability Scanning
    if "vuln_scan" not in completed:
        print("\n[4/6] Vulnerability Scanning")
        update_nuclei_templates()
        run_nuclei(alive_urls)
        run_afrog(alive_urls)
        check_takeover(subs)
        scan_js(alive_urls)
        if ENABLE_HEAVY_TOOLS:
            discover_parameters(alive_urls)
        mark_step("vuln_scan")
    else:
        print("\n[4/6] Skipping: vuln_scan (completed)")
    
    # Phase 5: Reporting
    print("\n[5/6] Generating Report")
    report_file, total_findings = generate_report()
    
    # Phase 6: Notification
    print("\n[6/6] Sending Alerts")
    msg = f"""✅ BOGART v6 Scan Complete
• Target: `{TARGET_DOMAIN}`
• Subdomains: {len(subs)}
• Alive Hosts: {len(alive_hosts)}
• Findings: {total_findings}
• Report: `{report_file}`"""
    send_telegram(msg)
    
    print("\n" + "=" * 70)
    print("[+] SCAN COMPLETE. REPORT GENERATED.")
    print("=" * 70)

# ==============================
# RUN IT
# ==============================
if __name__ == "__main__":
    # Ensure required tools are installed
    required_tools = ["massdns", "nuclei", "arjun", "waybackurls"]
    missing = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing.append(tool)
    
    if missing:
        print(f"[!] Missing tools: {missing}")
        print("Install with: go install -v github.com/projectdiscovery/{tool}@latest")
        if not ENABLE_HEAVY_TOOLS:
            print("[*] Heavy tools disabled. Continuing with basic recon...")
        else:
            sys.exit(1)
    
    asyncio.run(main())
