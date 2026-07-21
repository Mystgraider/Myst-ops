# secscan: disable-file
# (this file's before/after values are documentation strings that mimic
#  vulnerable patterns on purpose - not real executable code to flag)
"""
secure_coding_guide.py
-----------------------
Maps each detector rule id to a short secure-coding fix: what to do instead,
plus a minimal before/after snippet. Used by both the vulnerability report
and the educational secure-coding report.
"""

from typing import Dict

# Keyed by the *base* rule id (AST suffix stripped by the detector's dedupe step)
SECURE_CODING_GUIDE: Dict[str, dict] = {
    "HARD-001": dict(
        recommendation="Never commit literal credentials. Load secrets from environment "
                        "variables, a .env file (excluded via .gitignore), or a secrets manager.",
        before='API_KEY = "sk_live_abc123..."',
        after='import os\nAPI_KEY = os.environ["API_KEY"]',
    ),
    "CRYPTO-001": dict(
        recommendation="Use SHA-256 or better for integrity/checksums. For passwords, use a "
                        "purpose-built KDF: bcrypt, scrypt, or argon2 — never a raw fast hash.",
        before='hashlib.md5(password.encode()).hexdigest()',
        after='import bcrypt\nbcrypt.hashpw(password.encode(), bcrypt.gensalt())',
    ),
    "INJ-001": dict(
        recommendation="Avoid the shell entirely. Use subprocess with an argument list and "
                        "shell=False, and validate/allowlist any user-supplied values.",
        before='os.system(f"ping {host}")',
        after='subprocess.run(["ping", "-c", "4", host], shell=False, check=True)',
    ),
    "INJ-002": dict(
        recommendation="Pass command and arguments as a list; set shell=False (the default). "
                        "If a shell feature is truly required, strictly allowlist the input.",
        before='subprocess.run(f"tar -czf {name}.tar.gz {folder}", shell=True)',
        after='subprocess.run(["tar", "-czf", f"{name}.tar.gz", folder], shell=False)',
    ),
    "EVAL-001": dict(
        recommendation="Avoid eval/exec on any input that isn't fully trusted and controlled by "
                        "you. For data parsing use json.loads or ast.literal_eval for simple "
                        "Python literals.",
        before='eval(user_input)',
        after='import ast\nast.literal_eval(user_input)  # only for literals like dict/list/num',
    ),
    "DESER-001": dict(
        recommendation="Never unpickle data from an untrusted source. Prefer JSON or another "
                        "data-only format for anything crossing a trust boundary.",
        before='data = pickle.loads(request_body)',
        after='import json\ndata = json.loads(request_body)',
    ),
    "DESER-002": dict(
        recommendation="Use yaml.safe_load(), which restricts construction to simple Python "
                        "types and cannot instantiate arbitrary objects.",
        before='config = yaml.load(f)',
        after='config = yaml.safe_load(f)',
    ),
    "SQLI-001": dict(
        recommendation="Use parameterized queries / prepared statements. Never build SQL via "
                        "f-strings, %-formatting, or concatenation with user input.",
        before='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        after='cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
    ),
    "XSS-001": dict(
        recommendation="Let the templating engine auto-escape by default. Only mark content "
                        "safe after it has been explicitly sanitized (e.g. with bleach).",
        before='mark_safe(user_comment)',
        after='import bleach\nmark_safe(bleach.clean(user_comment, tags=["b", "i"]))',
    ),
    "RAND-001": dict(
        recommendation="Use the 'secrets' module for anything security-relevant: tokens, "
                        "password reset codes, API keys, session ids.",
        before='token = str(random.randint(100000, 999999))',
        after='import secrets\ntoken = secrets.token_urlsafe(32)',
    ),
    "DEBUG-001": dict(
        recommendation="Drive DEBUG from an environment variable that defaults to False, and "
                        "make sure production deployments never set it to True.",
        before='DEBUG = True',
        after='import os\nDEBUG = os.environ.get("DEBUG", "False") == "True"',
    ),
    "TLS-001": dict(
        recommendation="Keep certificate verification on. If you're hitting an internal CA, "
                        "point verify at the CA bundle instead of disabling verification.",
        before='requests.get(url, verify=False)',
        after='requests.get(url, verify="/path/to/internal-ca-bundle.pem")',
    ),
    "BIND-001": dict(
        recommendation="Bind to localhost (127.0.0.1) unless the service genuinely needs to be "
                        "reachable externally, and put it behind a firewall/reverse proxy if so.",
        before='app.run(host="0.0.0.0")',
        after='app.run(host="127.0.0.1")  # or a specific internal interface',
    ),
    "ASSERT-001": dict(
        recommendation="Replace security-relevant asserts with an explicit if/raise — asserts "
                        "are compiled out entirely when Python runs with the -O flag.",
        before='assert user.is_admin',
        after='if not user.is_admin:\n    raise PermissionError("Admin required")',
    ),
    "PATH-001": dict(
        recommendation="Resolve the final path and confirm it's still inside the intended base "
                        "directory before opening it.",
        before='open(os.path.join(base_dir, request.args["file"]))',
        after=(
            'target = os.path.realpath(os.path.join(base_dir, request.args["file"]))\n'
            'if not target.startswith(os.path.realpath(base_dir) + os.sep):\n'
            '    raise ValueError("Invalid path")'
        ),
    ),
    "XXE-001": dict(
        recommendation="Use a parser configured to reject external entities/DTDs (e.g. "
                        "defusedxml) when handling XML from an untrusted source.",
        before='xml.etree.ElementTree.parse(untrusted_file)',
        after='import defusedxml.ElementTree as ET\nET.parse(untrusted_file)',
    ),
}


def get_guidance(rule_id: str) -> dict:
    base_id = rule_id.replace("-AST", "")
    return SECURE_CODING_GUIDE.get(base_id, dict(
        recommendation="Review this finding manually; no canned guidance is available for this rule id.",
        before="", after="",
    ))
