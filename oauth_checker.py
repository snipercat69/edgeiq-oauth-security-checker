#!/usr/bin/env python3
"""
EdgeIQ Labs — OAuth 2.0 Security Checker
Detects OAuth misconfigurations, redirect URI flaws, state/csrf issues, PKCE support, and more.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Tuple, List, Dict

# ─────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────
_GRN = '\033[92m'; _YLW = '\033[93m'; _RED = '\033[91m'; _CYA = '\033[96m'
_BLD = '\033[1m'; _RST = '\033[0m'; _MAG = '\033[35m'

def ok(t):    return f"{_GRN}{t}{_RST}"
def warn(t):  return f"{_YLW}{t}{_RST}"
def fail(t):  return f"{_RED}{t}{_RST}"
def info(t):  return f"{_CYA}{t}{_RST}"
def bold(t):  return f"{_BLD}{t}{_RST}"

# ─────────────────────────────────────────────
# Licensing
# ─────────────────────────────────────────────
LICENSE_FILE = Path.home() / ".edgeiq" / "license.key"
VALID_LICENSES = {}

def load_licenses():
    global VALID_LICENSES
    if LICENSE_FILE.exists():
        key = LICENSE_FILE.read().strip()
        VALID_LICENSES[key] = "bundle"

def is_pro():
    load_licenses()
    env_key = os.environ.get("EDGEIQ_LICENSE_KEY", "").strip()
    if env_key in VALID_LICENSES:
        return True
    email = os.environ.get("EDGEIQ_EMAIL", "").strip().lower()
    if email in ("gpalmieri21@gmail.com",):
        return True
    return False

import os
def require_pro(feature=""):
    if is_pro():
        return True
    print()
    print(f"{_RED}╔{'═' * 56}╗")
    print(f"{_RED}║  🔒 Pro Feature                              ║".ljust(63) + "║")
    print(f"{_RED}╠{'═' * 56}╣")
    print(f"{_RED}║  This feature requires Pro or Bundle license.  ║".ljust(63) + "║")
    print(f"{_RED}║  Your current tier: FREE                       ║".ljust(63) + "║")
    print(f"{_RED}║                                                    ║".ljust(63) + "║")
    print(f"{_RED}║  Upgrade options:                                 ║".ljust(63) + "║")
    print(f"{_RED}║    Pro ($19/mo):   https://buy.stripe.com/aFa00l9i3bxrcUs18c7wA0k  ║".ljust(63) + "║")
    print(f"{_RED}║    Bundle ($39/mo): https://buy.stripe.com/aFabJ3am79pjg6E18c7wA02  ║".ljust(63) + "║")
    print(f"{_RED}╚{'─' * 56}╝")
    print()
    return False

# ─────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────
def make_request(url: str, timeout: int = 10) -> Tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; EdgeIQ-OAuth/1.0)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)

# ─────────────────────────────────────────────
# OAuth Analysis Functions
# ─────────────────────────────────────────────
def check_redirect_uris(uri: str) -> List[Dict]:
    issues = []
    parsed = urllib.parse.urlparse(uri)
    host = parsed.hostname or ""

    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        issues.append({"severity": "CRITICAL", "type": "localhost_redirect", "message": "Redirect URI allows localhost"})
    if "null" in uri.lower() or uri == "null":
        issues.append({"severity": "CRITICAL", "type": "null_redirect", "message": "Redirect URI is explicitly null"})
    if "*" in host or ".." in uri:
        issues.append({"severity": "HIGH", "type": "wildcard_redirect", "message": "Redirect URI contains wildcard or path traversal"})
    if parsed.scheme == "http" and "localhost" not in host:
        issues.append({"severity": "HIGH", "type": "http_redirect", "message": "Redirect URI uses HTTP (non-localhost)"})
    if parsed.path in ("/", "/callback", "/cb", "/redirect"):
        issues.append({"severity": "MEDIUM", "type": "generic_redirect", "message": "Redirect URI path is very generic"})
    if any(x in uri.lower() for x in ["client_secret", "password", "token"]):
        issues.append({"severity": "HIGH", "type": "sensitive_redirect", "message": "Redirect URI contains sensitive URL params"})
    return issues

def check_redirect_uri(uri: str) -> Dict:
    """Check redirect_uri for common misconfigurations."""
    issues = check_redirect_uris(uri)
    if issues:
        return {
            "severity": issues[0]["severity"],
            "type": "redirect_uri_issues",
            "message": f"{len(issues)} redirect URI issue(s) found: " + "; ".join(i["message"] for i in issues),
            "issues": issues,
        }
    return {
        "severity": "INFO",
        "type": "redirect_ok",
        "message": "Redirect URI appears secure",
        "issues": [],
    }

def check_state_param(auth_url: str) -> Dict:
    """Check if state parameter exists and is sufficiently random."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if "state" not in params:
        return {
            "severity": "HIGH",
            "type": "missing_state",
            "message": "State parameter missing — vulnerable to CSRF attacks",
        }

    state = params["state"]
    if len(state) < 16:
        return {
            "severity": "MEDIUM",
            "type": "weak_state",
            "message": f"State parameter is short ({len(state)} chars) — may be predictable",
        }

    # Check for common patterns (base64url but weak)
    if re.match(r'^[A-Za-z0-9_-]{16,32}$', state):
        return {
            "severity": "INFO",
            "type": "state_ok",
            "message": "State parameter present and appears random",
        }

    return {
        "severity": "INFO",
        "type": "state_ok",
        "message": "State parameter present",
    }

def check_pkce_support(auth_url: str) -> Dict:
    """Check PKCE (code_challenge) support in auth URL."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if "code_challenge" not in params:
        return {
            "severity": "MEDIUM",
            "type": "pkce_missing",
            "message": "PKCE (code_challenge) not present — authorization code may be vulnerable to interception",
        }

    method = params.get("code_challenge_method", "plain")
    if method == "S256":
        return {
            "severity": "INFO",
            "type": "pkce_ok",
            "message": "PKCE supported with S256 challenge method — strong protection",
        }
    elif method == "plain":
        return {
            "severity": "LOW",
            "type": "pkce_weak",
            "message": "PKCE present but uses 'plain' method — S256 recommended",
        }

    return {
        "severity": "INFO",
        "type": "pkce_ok",
        "message": "PKCE supported",
    }

def check_response_type(auth_url: str) -> Dict:
    """Check response_type for implicit flow or other risks."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    rt = params.get("response_type", "")
    if rt == "token":
        return {
            "severity": "HIGH",
            "type": "implicit_flow",
            "message": "Implicit flow (response_type=token) — bearer token exposed in URL fragment, high interception risk",
        }
    elif rt == "id_token":
        return {
            "severity": "MEDIUM",
            "type": "implicit_hybrid",
            "message": "Hybrid/implicit flow detected — tokens may be exposed",
        }
    elif "token" in rt:
        return {
            "severity": "MEDIUM",
            "type": "implicit_variant",
            "message": "Response type includes token — may expose bearer token",
        }

    return {
        "severity": "INFO",
        "type": "code_flow",
        "message": "Authorization code flow (secure default)",
    }

def check_scopes(auth_url: str) -> Dict:
    """Analyze requested scopes."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    scope = params.get("scope", "")
    if not scope:
        return {
            "severity": "INFO",
            "type": "no_scope",
            "message": "No explicit scope requested — authorization server will apply defaults",
        }

    scope_list = scope.split()
    warnings = []
    dangerous = ["admin", "root", "sudo", "*", "all", "full", "delete", "write-all"]
    sensitive = ["email", "profile", "phone", "address", "offline_access"]

    for s in scope_list:
        if s.lower() in dangerous:
            warnings.append(f"Dangerous scope: '{s}'")
        elif s.lower() in sensitive and "*" in s:
            warnings.append(f"Overly broad sensitive scope: '{s}'")

    if warnings:
        return {
            "severity": "MEDIUM",
            "type": "scope_warning",
            "message": f"Scopes: {', '.join(scope_list)} — {'; '.join(warnings)}",
        }

    return {
        "severity": "INFO",
        "type": "scope_ok",
        "message": f"Scopes: {', '.join(scope_list)}",
    }

def check_client_id_in_url(auth_url: str) -> Dict:
    """Check if client_id is present (standard) but flag if something sensitive is too."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if "client_id" not in params:
        return {
            "severity": "LOW",
            "type": "missing_client_id",
            "message": "client_id not found in auth URL — may be passed via POST body",
        }

    if "client_secret" in params:
        return {
            "severity": "CRITICAL",
            "type": "client_secret_exposed",
            "message": "client_secret found in authorization URL query params — NEVER pass secrets in URLs",
        }

    return {
        "severity": "INFO",
        "type": "client_id_ok",
        "message": "client_id present in authorization URL",
    }

def check_authorization_server(url: str) -> Dict:
    """Probe authorization server for security headers and capabilities."""
    status, body = make_request(url, timeout=8)
    if status == 0:
        return {
            "severity": "INFO",
            "type": "server_probe",
            "message": f"Could not probe authorization endpoint: {body[:80]}",
        }

    findings = []

    # Security headers
    csp = None
    x_frame = None
    hsts = None

    if "content-security-policy" in body.lower() or "CSP" in body:
        findings.append("CSP header present")
    if "x-frame-options" in body.lower() or "X-Frame" in body:
        findings.append("X-Frame-Options present")
    if "strict-transport-security" in body.lower() or "HSTS" in body:
        findings.append("HSTS header present")

    # TLS version hints
    if "tls" in body.lower() or "https" in body.lower():
        findings.append("HTTPS enforced")

    return {
        "severity": "INFO",
        "type": "server_probe",
        "message": f"Authorization server responses: {', '.join(findings) if findings else 'no special headers detected'}",
    }

# ─────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────
def scan(auth_url: str, pro: bool = False, bundle: bool = False,
         timeout: int = 10, output: Optional[str] = None) -> dict:
    print()
    print(f"{_CYA}{_BLD}╔{'═' * 54}╗{_RST}")
    print(f"{_CYA}{_BLD}║   OAuth 2.0 Security Checker — EdgeIQ Labs    ║{_RST}")
    print(f"{_CYA}{_BLD}╚{'═' * 54}╝{_RST}")
    print()

    if not auth_url.startswith("http"):
        auth_url = "https://" + auth_url

    print(f"  {_MAG}▶{_RST} Target: {bold(auth_url)}")
    tier = "BUNDLE" if bundle else ("PRO" if pro else "FREE")
    print(f"  {_MAG}▶{_RST} Tier: {tier}")
    print()

    results = {
        "url": auth_url,
        "checks": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "info": 0},
        "threat_level": "LOW",
    }

    checks = [
        ("Redirect URI Validation", lambda: check_redirect_uri(auth_url)),
        ("State Parameter Check", lambda: check_state_param(auth_url)),
        ("PKCE Support", lambda: check_pkce_support(auth_url)),
        ("Response Type Analysis", lambda: check_response_type(auth_url)),
        ("Scope Analysis", lambda: check_scopes(auth_url)),
        ("Client ID Security", lambda: check_client_id_in_url(auth_url)),
    ]

    if pro or bundle:
        checks.append(("Authorization Server Probe", lambda: check_authorization_server(auth_url)))

    for name, fn in checks:
        print(f"  {'─' * 40}")
        print(f"  {info('⏳')} {name}...")
        try:
            result = fn()
        except Exception as e:
            result = {"severity": "INFO", "type": "error", "message": f"Check error: {e}"}

        sev = result.get("severity", "INFO")
        msg = result.get("message", "")

        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟡", "LOW": "🟡", "INFO": "✔"}
        sev_color = {"CRITICAL": fail, "HIGH": warn, "MEDIUM": warn, "LOW": warn, "INFO": ok}
        icon = sev_icon.get(sev, "✔")
        color_fn = sev_color.get(sev, ok)

        print(f"  {icon} {name}: {color_fn(msg)}")
        results["checks"].append({"check": name, **result})
        results["summary"][sev.lower()] = results["summary"].get(sev.lower(), 0) + 1

    # Threat assessment
    c = results["summary"].get("critical", 0)
    h = results["summary"].get("high", 0)
    if c > 0:
        results["threat_level"] = "CRITICAL"
    elif h >= 2:
        results["threat_level"] = "HIGH"
    elif h >= 1:
        results["threat_level"] = "MEDIUM"

    # Summary
    print()
    print(f"  {'─' * 55}")
    print()
    threat = results["threat_level"]
    tc = _RED if threat == "CRITICAL" else (_YLW if threat in ("HIGH", "MEDIUM") else _GRN)
    print(f"=== Scan Complete ===")
    print(f"  Threat Level: {tc}{bold(threat)}{_RST}")
    print(f"  Critical: {fail(results['summary'].get('critical', 0))} | High: {warn(results['summary'].get('high', 0))} | Medium: {warn(results['summary'].get('medium', 0))} | Info: {ok(results['summary'].get('info', 0))}")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        print(f"  {ok('✔')} JSON report saved: {output}")

    print()
    return results

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EdgeIQ OAuth 2.0 Security Checker")
    parser.add_argument("--url", required=True, help="OAuth authorization URL with query params")
    parser.add_argument("--pro", action="store_true", help="Enable Pro features")
    parser.add_argument("--bundle", action="store_true", help="Enable Bundle features")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    parser.add_argument("--output", help="Write JSON report to file")
    args = parser.parse_args()

    import os
    scan(args.url, pro=args.pro, bundle=args.bundle, timeout=args.timeout, output=args.output)