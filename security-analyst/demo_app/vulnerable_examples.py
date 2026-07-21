"""
vulnerable_examples.py
------------------------
⚠️ INTENTIONALLY INSECURE CODE. Do not deploy or reuse any of this.

This file exists purely as a fixture so the scanner's rules can be verified
against known-bad patterns (the same way linter/SAST test suites include
"bad" sample files). It contains no working exploit against any real
system -- it's just isolated snippets demonstrating each anti-pattern the
detector looks for.
"""

import hashlib
import os
import pickle
import random
import subprocess
import xml.etree.ElementTree

import yaml

# HARD-001: hardcoded credential
password = "SuperSecret123"
API_KEY = "sk_live_abcdef123456"

# CRYPTO-001: weak hash for a password
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# INJ-001: command injection via os.system
def ping_host(host):
    os.system(f"ping -c 4 {host}")

# INJ-002: subprocess shell=True
def make_archive(name, folder):
    subprocess.run(f"tar -czf {name}.tar.gz {folder}", shell=True)

# EVAL-001: eval on external input
def calculate(expression):
    return eval(expression)

# DESER-001: unpickling untrusted data
def load_session(blob):
    return pickle.loads(blob)

# DESER-002: unsafe yaml.load
def load_config(path):
    with open(path) as f:
        return yaml.load(f)

# SQLI-001: string-formatted SQL query
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

# RAND-001: predictable token generation
def generate_token():
    return str(random.randint(100000, 999999))

# DEBUG-001: debug mode left on
DEBUG = True

# TLS-001: certificate verification disabled
def fetch(url):
    import requests
    return requests.get(url, verify=False)

# BIND-001: bound to all interfaces
def run_server(app):
    app.run(host="0.0.0.0")

# ASSERT-001: security check via assert
def require_admin(user):
    assert user.is_admin

# PATH-001: path traversal via unsanitized user-supplied filename
def read_uploaded_file(request, base_dir):
    return open(os.path.join(base_dir, request.args["filename"]))

# XXE-001: XML parsed without disabling external entities
def parse_uploaded_xml(untrusted_file):
    return xml.etree.ElementTree.parse(untrusted_file)
