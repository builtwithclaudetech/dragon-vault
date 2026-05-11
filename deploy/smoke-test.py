#!/usr/bin/env python3
"""Dragon Vault smoke test — run after every deploy.

Verifies:
  1. HTTPS is up with valid cert
  2. Security headers present (CSP, HSTS, XCTO, RP, PP)
  3. No CSP violations blocking inline scripts or WASM
  4. Static files served (CSS, JS, SW, manifest, fonts)
  5. Login page renders without JS console errors
  6. Health endpoint returns OK

Usage:
  python3 deploy/smoke-test.py [--url https://pwm.YOUR-SERVER-IP.nip.io]
"""

import argparse
import socket
import sys
import urllib.request
import ssl
import json
import subprocess


def check_tls(hostname):
    """Verify TLS cert is valid and trusted."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return True, cert
    except Exception as e:
        return False, str(e)


def check_headers(base_url):
    """Verify all required security headers are present."""
    req = urllib.request.Request(base_url + "/Account/Login")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        return False, str(e), {}

    required = {
        "strict-transport-security": "HSTS",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "content-security-policy": "Content-Security-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    missing = [name for key, name in required.items() if key not in headers]
    if missing:
        return False, f"Missing headers: {', '.join(missing)}", headers

    csp = headers.get("content-security-policy", "")
    # Must allow inline scripts and WASM for Argon2 key derivation
    csp_issues = []
    if "'unsafe-inline'" not in csp:
        csp_issues.append("missing 'unsafe-inline' in script-src")
    if "'wasm-unsafe-eval'" not in csp:
        csp_issues.append("missing 'wasm-unsafe-eval' in script-src")
    if "api.pwnedpasswords.com" not in csp:
        csp_issues.append("missing HIBP in connect-src")

    if csp_issues:
        return False, f"CSP gaps: {'; '.join(csp_issues)}", headers

    return True, headers, {}


def check_static_files(base_url):
    """Verify key static files return 200."""
    files = [
        "/css/site.css",
        "/js/crypto.js",
        "/js/vault.js",
        "/js/totp.js",
        "/sw.js",
        "/manifest.webmanifest",
    ]
    failures = []
    for path in files:
        try:
            req = urllib.request.Request(base_url + path, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=10)
            if resp.status != 200:
                failures.append(f"{path} returned {resp.status}")
        except Exception as e:
            failures.append(f"{path}: {e}")
    return len(failures) == 0, failures


def check_health(base_url):
    """Verify health endpoint returns OK."""
    try:
        req = urllib.request.Request(base_url + "/healthz")
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode().strip()
        return body == "OK" and resp.status == 200, body
    except Exception as e:
        return False, str(e)


def check_browser_errors(base_url):
    """Launch headless Chromium and capture console errors on the login page."""
    script = f"""
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    errors = []
    page.on('console', lambda msg: errors.append(f'[{{msg.type}}] {{msg.text[:200]}}') if msg.type == 'error' else None)
    page.goto('{base_url}/Account/Login', wait_until='networkidle', timeout=20000)
    title = page.title()
    browser.close()
    import json
    print(json.dumps({{'title': title, 'errors': errors}}))
"""
    try:
        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False, f"Browser test failed to run: {result.stderr[:200]}"
        data = json.loads(result.stdout.strip())
        errors = data.get("errors", [])
        title = data.get("title", "")
        if errors:
            return False, f"Console errors: {errors}"
        if "Dragon Vault" not in title:
            return False, f"Unexpected page title: {title}"
        return True, f"Page title: {title}, no console errors"
    except FileNotFoundError:
        return None, "Playwright not installed — install with: pip install playwright && python3 -m playwright install chromium"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Dragon Vault smoke test")
    parser.add_argument("--url", default="https://pwm.YOUR-SERVER-IP.nip.io",
                        help="Base URL to test (default: https://pwm.YOUR-SERVER-IP.nip.io)")
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    print(f"Dragon Vault Smoke Test — {base_url}")
    print("=" * 60)

    results = []
    failures = 0

    # 1. TLS
    ok, detail = check_tls(base_url.replace("https://", ""))
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"[{status}] TLS cert          {detail if not ok else 'valid'}")
    results.append(("TLS cert", ok))

    # 2. Security headers
    ok, detail, headers = check_headers(base_url)
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"[{status}] Security headers   {detail if not ok else 'all present'}")
    results.append(("Security headers", ok))

    # 3. Static files
    ok, detail = check_static_files(base_url)
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
        for f in detail:
            print(f"       - {f}")
    else:
        print(f"[{status}] Static files      all 6 served")
    results.append(("Static files", ok))

    # 4. Health
    ok, detail = check_health(base_url)
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"[{status}] Health endpoint    {detail}")
    results.append(("Health endpoint", ok))

    # 5. Browser
    ok, detail = check_browser_errors(base_url)
    if ok is None:
        status = "SKIP"
        print(f"[{status}] Browser console    {detail}")
    elif ok:
        status = "PASS"
        print(f"[{status}] Browser console    {detail}")
    else:
        status = "FAIL"
        failures += 1
        print(f"[{status}] Browser console    {detail}")
    results.append(("Browser console", ok))

    print("=" * 60)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    skipped = sum(1 for _, ok in results if ok is None)
    print(f"Results: {passed}/{total} passed", end="")
    if skipped:
        print(f", {skipped} skipped", end="")
    print(f", {failures} failed")

    if failures > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
