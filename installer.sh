#!/bin/bash

echo "================================================================="
echo " JavaScript Analysis Tools Installation Script (Fixed)"
echo "================================================================="

TOOLS_DIR="$HOME/js_analysis_tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR" || exit

echo "[+] Installing system dependencies..."
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv nodejs npm curl jq ruby

# --- Setup Virtual Environment for Python tools ---
echo "[+] Setting up Python virtual environment..."
python3 -m venv "$TOOLS_DIR/venv"
source "$TOOLS_DIR/venv/bin/activate"

echo "[+] Installing LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder || exit
"$TOOLS_DIR/venv/bin/pip" install -r requirements.txt
cd ..

echo "[+] Installing SecretFinder..."
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder || exit
"$TOOLS_DIR/venv/bin/pip" install -r requirements.txt
cd ..

echo "[+] Installing JSScanner..."
git clone https://github.com/0x240x23elu/JSScanner.git
cd JSScanner || exit
"$TOOLS_DIR/venv/bin/pip" install -r requirements.txt
cd ..

echo "[+] Installing truffleHog..."
"$TOOLS_DIR/venv/bin/pip" install truffleHog

echo "[+] Installing js-beautify (Node)..."
sudo npm install -g js-beautify --unsafe-perm=true

echo "[+] Installing JSScan..."
git clone https://github.com/zseano/JS-Scan.git

echo "[+] Installing relative-url-extractor..."
git clone https://github.com/jobertabma/relative-url-extractor.git

echo "[+] Installing endpoints-finder..."
mkdir -p endpoints-finder

cat > endpoints-finder/endpoints.py << 'EOL'
#!/usr/bin/env python3
# ==============================================================
#  Advanced JS Endpoint & Secret Extractor (fixed)
#  - suppresses urllib3 InsecureRequestWarning
#  - prints endpoints & secrets to terminal per-file
#  - improved regexes, reduced false positives
#  - saves JSON, all_endpoints.txt, all_secrets.txt
#  Version: 2.3
# ==============================================================

import sys
import re
import requests
from urllib.parse import urlparse
import argparse
import json
import os
import urllib3

# ---------------------------
# Suppress insecure request warnings when verify=False is used
# ---------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------
# Settings
# ---------------------------
REQUEST_TIMEOUT = 10

# ANSI colors for clarity
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ---------------------------
# Endpoint Extraction
# ---------------------------
def extract_endpoints(content):
    endpoint_patterns = [
        # relative and absolute URL strings
        r'(?:"|\'|\`)(\/[a-zA-Z0-9_\-\/\.]+\??[^"\'\`]*)?(?:"|\'|\`)',
        r'(?:"|\'|\`)(https?:\/\/[^\s"\'\`]+)(?:"|\'|\`)',

        # fetch/ajax/axios calls
        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$.ajax|XMLHttpRequest\(\))\s*\(\s*(?:["\'`])?(https?:\/\/[^"\'`,\s)]+|\/[^"\'`,\s)]+)',
        # attributes
        r'(?:href|src|action)\s*[:=]\s*(?:["\'`])?(\/[^"\'`>\s]+|https?:\/\/[^"\'`>\s]+)',
        # jQuery-like shorthand .get('/api/...')
        r'\.(?:get|post|put|delete|patch)\s*\(\s*(?:["\'`])?(\/[^"\'`,\s)]+|https?:\/\/[^"\'`,\s)]+)',
        # router path definitions
        r'path\s*(?::|=)\s*(?:["\'`])?(\/[^"\'`,\s)]+)'
    ]

    found = set()
    for pattern in endpoint_patterns:
        for match in re.findall(pattern, content):
            # re.findall with patterns above may return tuples or strings
            if isinstance(match, tuple):
                # take first non-empty capture
                capture = next((m for m in match if m and m.strip()), "")
            else:
                capture = match
            if capture:
                cleaned = capture.strip()
                # normalize trailing quotes, commas or trailing ?params broken earlier
                cleaned = cleaned.rstrip('",\' ')
                # ignore common single-char or nonsense
                if len(cleaned) > 1:
                    found.add(cleaned)
    return sorted(found)


# ---------------------------
# Secret Extraction
# ---------------------------
def extract_secrets(content):
    # refined patterns with grouping where appropriate; avoid tiny matches
    secret_patterns = {
        # Ahmed Elheny inspired generic capture (keyword + key)
        "KEYWORD_VALUE": r'(?i)\b(?:api|access|auth|secret|token|key|credential|pwd|password|client|bearer|pass)[_\-\s:]*[=:\s]{0,2}[\'"]?([A-Za-z0-9\-\._\/\+]{8,200})[\'"]?',
        # common providers/formats
        "AWS_ACCESS_KEY_ID": r'AKIA[0-9A-Z]{16}',
        "AWS_SECRET_ACCESS_KEY": r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
        "FIREBASE_API_KEY": r'AIza[0-9A-Za-z\-_]{35}',
        "GOOGLE_CLIENT_ID": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        "SLACK_TOKEN": r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,64}',
        "STRIPE_SECRET_KEY": r'sk_live_[0-9a-zA-Z]{24,50}',
        "STRIPE_PUBLISHABLE_KEY": r'pk_live_[0-9a-zA-Z]{24,50}',
        "GITHUB_TOKEN": r'(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z_]{36,72}',
        "JWT": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+',
        "PRIVATE_KEY": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        "BASIC_AUTH": r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]+',
        "BEARER_TOKEN": r'Authorization:\s*Bearer\s+[A-Za-z0-9\._\-]+',
        "URL_CREDENTIALS": r'https?:\/\/[^/:\s]+:[^@/\s]+@[^/\s]+',
        # long base64-like strings (>= 40 chars)
        "BASE64_LIKELY": r'[\'"]([A-Za-z0-9+/]{40,}=*)[\'"]'
    }

    found = []
    for name, pattern in secret_patterns.items():
        for m in re.findall(pattern, content):
            # m may be a tuple or string
            value = m if not isinstance(m, tuple) else next((x for x in m if x), "")
            if not value:
                continue
            # filter obviously-bad short words or simple JS function names
            if len(value) < 8:
                continue
            # reject purely alphabetic short words (likely false positive)
            if re.fullmatch(r'[A-Za-z]{1,25}', value):
                continue
            # final sanity: no long runs of punctuation only
            if re.fullmatch(r'[\W_]+', value):
                continue
            found.append({"type": name, "value": value})
    # deduplicate while preserving order
    seen = set()
    dedup = []
    for item in found:
        key = (item["type"], item["value"])
        if key not in seen:
            seen.add(key)
            dedup.append(item)
    return dedup


# ---------------------------
# Process single JS URL
# ---------------------------
def process_js_url(js_url, timeout):
    try:
        print(f"{CYAN}[*] Processing:{RESET} {js_url}")
        resp = requests.get(js_url, timeout=timeout, verify=False)
        if resp.status_code != 200:
            print(f"    {YELLOW}[!] HTTP {resp.status_code} - skipping content extraction{RESET}")
            return {"url": js_url, "endpoints": [], "secrets": []}

        content = resp.text

        endpoints = extract_endpoints(content)
        secrets = extract_secrets(content)

        # Print counts and details to terminal
        print(f"    {GREEN}Endpoints:{RESET} {len(endpoints)}", end="")
        if endpoints:
            print()
            for e in endpoints:
                print(f"      - {e}")
        else:
            print(" (none)")

        print(f"    {RED}Secrets:{RESET} {len(secrets)}", end="")
        if secrets:
            print()
            for s in secrets:
                print(f"      - [{s['type']}] {s['value']}")
        else:
            print(" (none)")

        return {"url": js_url, "endpoints": endpoints, "secrets": secrets}

    except requests.exceptions.RequestException as rexc:
        print(f"    {YELLOW}[!] Request error: {rexc}{RESET}")
        return {"url": js_url, "endpoints": [], "secrets": []}
    except Exception as exc:
        print(f"    {RED}[!] Unexpected error: {exc}{RESET}")
        return {"url": js_url, "endpoints": [], "secrets": []}


# ---------------------------
# Main CLI
# ---------------------------
def main():
    global REQUEST_TIMEOUT

    parser = argparse.ArgumentParser(description="Advanced JS Endpoint & Secret Extractor")
    parser.add_argument("-i", "--input", required=True, help="Input file with JS URLs (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-t", "--timeout", type=int, default=REQUEST_TIMEOUT, help="HTTP request timeout (seconds)")
    args = parser.parse_args()

    REQUEST_TIMEOUT = args.timeout
    outdir = args.output
    os.makedirs(outdir, exist_ok=True)

    with open(args.input, "r") as fh:
        urls = [line.strip() for line in fh if line.strip()]

    results = []
    for u in urls:
        r = process_js_url(u, REQUEST_TIMEOUT)
        results.append(r)

    # write JSON
    with open(os.path.join(outdir, "detailed_results.json"), "w") as jf:
        json.dump(results, jf, indent=2)

    # write endpoints flat file
    with open(os.path.join(outdir, "all_endpoints.txt"), "w") as ef:
        for r in results:
            for e in r["endpoints"]:
                ef.write(e + "\n")

    # write secrets flat file
    with open(os.path.join(outdir, "all_secrets.txt"), "w") as sf:
        for r in results:
            for s in r["secrets"]:
                sf.write(f"Type: {s['type']}, Value: {s['value']}, URL: {r['url']}\n")

    print(f"\n{GREEN}[+] Done.{RESET} Results saved to: {outdir}\n")


if __name__ == "__main__":
    main()
EOL
chmod +x endpoints-finder/endpoints.py

echo "[+] Adding alias..."
if ! grep -q "js_analysis_tools/venv/bin" ~/.bashrc; then
    echo 'export PATH="$PATH:$HOME/js_analysis_tools/venv/bin:$HOME/js_analysis_tools/endpoints-finder"' >> ~/.bashrc
    source ~/.bashrc
fi

echo "================================================================="
echo " Installation Complete!"
echo "================================================================="
echo "Tools installed in: $TOOLS_DIR"
echo "Activate Python venv using: source $TOOLS_DIR/venv/bin/activate"
echo "Then use: ./analyze_js.sh <js_urls.txt>"
echo
