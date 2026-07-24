import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analyzer.code_scanner import scan_path
from analyzer.vulnerability_detector import run_ast_checks


class ScannerTests(unittest.TestCase):
    def test_scans_javascript_and_typescript_sources(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            js_path = os.path.join(tmpdir, "client.js")
            ts_path = os.path.join(tmpdir, "redirect.ts")
            with open(js_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "const api_key = 'abc123';\n"
                    "document.body.innerHTML = userInput;\n"
                    "exec(userInput);\n"
                )
            with open(ts_path, "w", encoding="utf-8") as handle:
                handle.write("window.location.href = nextUrl;\n")

            rule_ids = {finding.rule_id for finding in scan_path(tmpdir, verbose=False)}

        self.assertIn("HARD-001", rule_ids)
        self.assertIn("JS-XSS-001", rule_ids)
        self.assertIn("JS-INJ-001", rule_ids)
        self.assertIn("JS-REDIR-001", rule_ids)

    def test_ast_checks_skip_non_python_files(self):
        self.assertEqual(run_ast_checks("example.js", "eval(userInput);"), [])

    def test_nosec_suppresses_single_line(self):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write("const token = 'abc123'; // nosec\n")
            path = handle.name
        try:
            self.assertEqual(scan_path(path, verbose=False), [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
