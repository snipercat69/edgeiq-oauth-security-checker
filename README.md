# 🔐 EdgeIQ OAuth Security Checker

**Detect OAuth 2.0 misconfigurations and security flaws in web applications.**

Checks redirect URI validation, state parameter integrity, PKCE support, token endpoint security, scope permissions, and implicit flow exposure — comprehensive OAuth auditing.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Audits OAuth 2.0 implementations for common security misconfigurations: redirect URI validation flaws, missing state parameters, absent PKCE, overly broad scopes, and implicit flow bearer token exposure.

> ⚠️ **Legal Notice:** Only test OAuth integrations you own or have explicit written authorization to audit.

---

## Key Features

- **Redirect URI validation** — tests for localhost, null, and wildcard misconfigs
- **State parameter check** — detects missing or weak CSRF protection
- **PKCE support detection** — identifies apps missing code challenge
- **Token endpoint security** — checks TLS, token format, expiration
- **Scope analysis** — flags overly broad permissions
- **Implicit flow detection** — warns about bearer token exposure
- **Authorization server fingerprinting** — identifies provider and version
- **JSON export** — structured audit results

---

## Prerequisites

- Python 3.8+
- `requests` library

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-oauth-security-checker.git
cd edgeiq-oauth-security-checker
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Check a site's OAuth configuration
python3 oauth_checker.py --domain example.com

# Audit a specific authorization endpoint
python3 oauth_checker.py --auth-url "https://auth.example.com/authorize" --client-id "your_client_id"

# JSON audit report
python3 oauth_checker.py --domain example.com --format json --output oauth-audit.json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 5 URIs/month, basic checks |
| **Lifetime** | $39 one-time | Unlimited audits, full analysis, provider fingerprinting |
| **Monthly** | $7/mo | All Lifetime features, billed monthly |

---

## Integration with EdgeIQ Tools

- **[EdgeIQ API Endpoint Discovery](https://github.com/snipercat69/edgeiq-api-endpoint-discovery)** — audit discovered OAuth flows
- **[EdgeIQ Alerting System](https://github.com/snipercat69/edgeiq-alerting-system)** — alert on OAuth findings

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-oauth-security-checker/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
