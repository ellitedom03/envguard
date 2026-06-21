# Gumroad Listing — EnvGuard

## Title
EnvGuard — Codebase Secrets Scanner (Catch Leaked API Keys Before Git Does)

## Price
$9.00

## Category
Software Development > Security & DevSecOps

## Description
One exposed AWS key can cost you thousands in crypto mining bills. One leaked `.env` file and your startup is on Hacker News for the wrong reasons.

EnvGuard scans your entire codebase for exposed secrets in seconds. It detects AWS keys, GitHub tokens, Stripe keys, Google API keys, private keys, database URLs, bot tokens, and 20+ other secret types before they ever reach production.

Run it before every commit. Add it to your CI/CD pipeline. Sleep better.

### Catches:
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Google API Keys & OAuth IDs
- Stripe Live & Test Keys
- Private Keys (RSA, EC, SSH, PGP)
- Database Connection Strings
- Discord, Telegram, Slack Bot Tokens
- JWT Tokens & Bearer Tokens
- PayPal, Twilio, SendGrid, NPM Secrets
- Hardcoded Passwords & API Keys

### Features:
- **25+ high-confidence patterns** — catches what other scanners miss
- **JSON output** — integrate with any CI/CD pipeline
- **Smart filtering** — auto-skips node_modules, .git, binaries, test fixtures
- **Masked output** — never leaks secrets to your console
- **Exit codes** — breaks your build if secrets are found (CI/CD ready)
- **File filtering** — scan only specific file types

### Perfect For:
- Solo developers who push to public repos
- Startup teams without a security engineer
- CI/CD pipelines (add to GitHub Actions in 2 lines)
- Code review workflows

### What You Get:
- envguard.py — the full scanner (MIT License)
- 25+ detection patterns, regularly updated
- Runs on any Python project — zero dependencies

## Tags
security, devsecops, secrets, api-keys, scanner, developer-tools, python, ci-cd, github, security-tools, dev-tools

## Files Included
envguard.py (MIT License)