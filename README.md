# OAuth Security Checker — CLI Setup

A OAuth 2.0 security misconfiguration scanner for web applications you own or have permission to audit.

## Prerequisites

- Python 3.8+

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-oauth-security-checker.git
cd edgeiq-oauth-security-checker
```

## Quick Start

```bash
# Free scan
python3 oauth_checker.py --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code&scope=read"

# Pro scan
EDGEIQ_EMAIL=your_email@gmail.com python3 oauth_checker.py \
  --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code&scope=read write" \
  --pro

# Bundle scan with JSON export
EDGEIQ_EMAIL=your_email@gmail.com python3 oauth_checker.py \
  --url "https://example.com/oauth/authorize?client_id=YOUR_ID&redirect_uri=https://example.com/callback&response_type=code" \
  --bundle --output oauth-report.json
```

## Features

- Redirect URI validation (localhost, null, wildcard checks)
- State parameter CSRF protection check
- PKCE support detection
- Response type analysis (implicit flow warnings)
- Scope permission analysis
- Authorization server security probing
- JSON export for reporting

## ⚠️ Legal Notice

Only audit OAuth integrations you own or have explicit written authorization to test.

## Licensing

Free tier: basic checks (5 URIs).

Pro ($19/mo) or Bundle ($39/mo): [buy.stripe.com/aFa00l9i3bxrcUs18c7wA0k](https://buy.stripe.com/aFa00l9i3bxrcUs18c7wA0k)