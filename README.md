# EnvGuard — Secrets & Sensitive Data Scanner

**Don't let your API keys end up on GitHub. Scan your codebase in seconds.**

## What It Does

EnvGuard scans your entire codebase for exposed secrets before they reach production or get committed to git. It catches 25+ types of sensitive data:

- AWS keys, GitHub tokens, Google API keys
- Stripe live/test keys, PayPal secrets
- Private keys (RSA, EC, SSH, PGP)
- Database connection strings
- Discord/Telegram/Slack bot tokens
- JWT tokens, bearer tokens, authorization headers
- Hardcoded passwords and generic API keys

## Why Developers Need This

GitHub scans 50M+ repos daily for leaked secrets. AWS keys get stolen and used for crypto mining within minutes. One exposed `.env` file = thousands in cloud bills.

EnvGuard catches what git hooks miss. Run it before every commit. Peace of mind for $9.

## Features

- 25+ high-confidence detection patterns (AWS, GitHub, Stripe, Google, etc.)
- 11 medium-confidence informational patterns (emails, IPs, internal URLs)
- Auto-skips node_modules, .git, build artifacts, binary files
- JSON output for CI/CD pipelines (exits with code 1 if secrets found)
- Masked output — never prints full secrets to console
- Smart filtering — skips test fixtures, example placeholders, mock data
- File extension filtering (scan only .py, .js, .ts, etc.)

## Quick Start

```bash
# Scan current directory
python envguard.py .

# Scan with JSON output (for CI/CD)
python envguard.py . --json

# Only scan Python and JavaScript files
python envguard.py /path/to/project --ext .py,.js

# Strict mode — only critical findings
python envguard.py . --strict

# Save report to file
python envguard.py . -o scan-report.txt
```

## Use in CI/CD (GitHub Actions)

```yaml
- name: Scan for secrets
  run: python envguard.py . --json --strict
```

## Pricing

**$9** — one-time purchase. Unlimited projects. Lifetime updates.

## What You Get

- `envguard.py` — The scanner (MIT license)
- 25+ detection patterns, maintained and updated
- CI/CD-ready with exit codes and JSON output

---

Created by HamdenTwins Digital
---

## Support

If this tool saves you time, consider [sponsoring](https://github.com/sponsors/ellitedom03) or buying me a coffee at [ko-fi.com/hamdentwins](https://ko-fi.com/hamdentwins).

Created by [HamdenTwins Digital](https://payhip.com/HamdenTwinsDigital)

---
