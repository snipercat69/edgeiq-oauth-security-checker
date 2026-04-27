# OAuth Security Checker

**Skill Name:** `oauth-security-checker`
**Version:** `1.0.0`
**Category:** Security / Vulnerability Assessment
**Price:** **Lifetime: $39** / Optional Monthly: $7/mo (includes all Pro features permanently)
**Author:** EdgeIQ Labs
**OpenClaw Compatible:** Yes — Python 3, pure stdlib, WSL + Linux

---

## What It Does

Detects OAuth 2.0 misconfigurations, security flaws, and authorization issues in web applications. Checks redirect URI validation, token endpoint security, scope permissions, PKCE support, state parameter integrity, and more.

> ⚠️ **Legal Notice:** Only test OAuth integrations you own or have explicit written authorization to audit.

---

## Features

- **Redirect URI validation** — tests for `localhost`, `null`, and wildcard misconfigs
- **State parameter check** — detects missing or weak CSRF protection
- **PKCE support detection** — identifies apps missing code challenge
- **Token endpoint security** — checks TLS, token format, expiration
- **Scope analysis** — flags overly broad permissions
- **Implicit flow detection** — warns about bearer token exposure
- **Authorization server fingerprinting** — identifies provider and version
- **JSON export** — structured results for reporting

---

## Tier Comparison

| Feature | Free | **Lifetime ($39)** | Optional Monthly ($7/mo) |
|---------|------|----------------|----------------------|
| Redirect URI checks | ✅ (5 URIs) | ✅ (unlimited) | ✅ (unlimited) |
| State parameter test | ✅ | ✅ | ✅ |
| PKCE detection | ✅ | ✅ | ✅ |
| Token endpoint analysis | ✅ | ✅ | ✅ |
| Scope permission analysis | ✅ | ✅ | ✅ |
| Full OAuth provider fingerprint | ✅ | ✅ | ✅ |
| JSON export | ✅ | ✅ | ✅ |

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/oauth-security-checker ~/.openclaw/skills/oauth-security-checker
```

---

## Usage

### Basic scan (free tier)

```bash
python3 oauth_checker.py --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code&scope=read"
```

### Pro scan with full analysis

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 oauth_checker.py \
  --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code&scope=read write" \
  --pro
```

### JSON report output

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 oauth_checker.py \
  --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code" \
  --bundle --output oauth-report.json
```

### As OpenClaw Discord Command

In `#edgeiq-support` channel:
```
!oauth https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code&scope=read
!oauth https://example.com/oauth/authorize?client_id=YOUR_ID --pro
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | string | — | Authorization URL with query params |
| `--pro` | flag | False | Enable Pro features |
| `--bundle` | flag | False | Enable Bundle features |
| `--output` | string | — | Write JSON report to file |
| `--timeout` | int | 10 | Request timeout (seconds) |

---

## Output Example

```
=== OAuth Security Checker ===
Target: https://example.com/oauth/authorize

  [1m[91m🔴 CRITICAL: Redirect URI allows localhost[0m
    Pattern: https://localhost/callback
    Risk: Attacker can intercept authorization codes

  [1m[93m🟡 WARNING: State parameter not detected[0m
    Risk: CSRF attack possible via authorization hijacking

  [1m[92m✔ OK: PKCE is supported[0m
    Challenge method: S256

  [1m[92m✔ OK: Token endpoint requires TLS[0m
    Version: TLS 1.2+

  [1m[93m🟡 INFO: Scopes detected: read, write, admin[0m
    Warning: 'admin' scope is overly broad

  Threat Level: HIGH — 2 issues found
```

---

## Pricing

**Lifetime License: $39** — your tool forever, all features included permanently.
**Optional Monthly: $7/mo** — for those who prefer recurring billing (cancel anytime).
👉 [Buy Lifetime — $39](https://buy.stripe.com/3cI28t2TFdFz7A88AE7wA0P)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/aFaeVfcuffNH7A8g367wA16)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/aFaeVfcuffNH7A8g367wA16)

## Pro Upgrade *(deprecated)*
All features now included in Lifetime purchase.

---

## Support

Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com)

---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
