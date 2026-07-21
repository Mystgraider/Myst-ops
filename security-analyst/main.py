#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - Security Analyst CLI
---------------------------------
Usage:
    python main.py scan <path>              Scan a file or directory
    python main.py scan <path> --no-db      Scan without saving to the findings DB
    python main.py demo                     Run the scanner against demo_app/ to sanity-check rules
    python main.py history                  List past scans stored in the DB
"""

import argparse
import sys

import config
from analyzer.code_scanner import scan_path
from database import findings_db
from reports import vulnerability_report, secure_coding_report


def cmd_scan(args):
    print("=" * 70)
    print("🛡️  SECURITY ANALYST - Static Code Review")
    print("=" * 70)

    findings = scan_path(args.path, verbose=True)
    scan_id = findings_db.new_scan_id()

    if not args.no_db:
        # files_scanned isn't tracked by scan_path's return value directly,
        # so we recompute a rough count from unique file paths in findings
        # plus at least 1 if nothing was found but the path is a single file.
        files_scanned = len({f.file_path for f in findings}) or 1
        findings_db.save_scan(scan_id, args.path, findings, files_scanned)
        print(f"[+] Saved to findings DB under scan_id={scan_id}")

    vuln_report_path = vulnerability_report.save_report(findings, args.path, scan_id)
    edu_report_path = secure_coding_report.save_report(findings, args.path, scan_id)

    print("\n" + "=" * 70)
    print(f"[+] Scan complete: {len(findings)} finding(s)")
    print(f"    Vulnerability report : {vuln_report_path}")
    print(f"    Secure coding report  : {edu_report_path}")
    print("=" * 70)


def cmd_demo(args):
    print("[*] Running demo scan against demo_app/vulnerable_examples.py")
    print("    (expected: every rule should fire at least once)\n")
    args.path = "demo_app/vulnerable_examples.py"
    args.no_db = args.no_db if hasattr(args, "no_db") else False
    cmd_scan(args)


def cmd_history(args):
    scans = findings_db.list_scans()
    if not scans:
        print("[*] No scans recorded yet. Run `python main.py scan <path>` first.")
        return
    print(f"{'SCAN ID':<20} {'TARGET':<40} {'FILES':>6} {'FINDINGS':>9} {'TIMESTAMP'}")
    for s in scans:
        print(f"{s['scan_id']:<20} {s['target_path']:<40} {s['files_scanned']:>6} {s['total_findings']:>9} {s['timestamp']}")


def main():
    parser = argparse.ArgumentParser(description="Security Analyst - static code vulnerability scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("path", help="Path to a source file or directory")
    scan_parser.add_argument("--no-db", action="store_true", help="Don't persist results to the findings DB")
    scan_parser.set_defaults(func=cmd_scan)

    demo_parser = subparsers.add_parser("demo", help="Scan the bundled vulnerable_examples.py to verify rules fire")
    demo_parser.add_argument("--no-db", action="store_true", help="Don't persist results to the findings DB")
    demo_parser.set_defaults(func=cmd_demo)

    history_parser = subparsers.add_parser("history", help="List past scans")
    history_parser.set_defaults(func=cmd_history)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
