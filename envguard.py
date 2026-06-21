#!/usr/bin/env python3
"""
EnvGuard — Secrets & Sensitive Data Scanner
===========================================
Scans your codebase for exposed API keys, tokens, passwords,
private keys, and other sensitive data before they reach production.

Catches what git hooks miss. One command, instant report.

Author: HamdenTwins Digital
License: MIT
Version: 1.0.0
"""

import os
import re
import sys
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

VERSION = "1.0.0"

# ─── Detection Patterns ─────────────────────────────────────

# High-confidence secret patterns
HIGH_CONFIDENCE_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}(?:secret|key).{0,20}['\"]?([0-9a-zA-Z/+]{40})['\"]?",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,255}",
    "GitHub App Token": r"gh[a-z]_[A-Za-z0-9_]{36,255}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,99}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,99}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "Private Key (EC)": r"-----BEGIN EC PRIVATE KEY-----",
    "Private Key (DSA)": r"-----BEGIN DSA PRIVATE KEY-----",
    "Private Key (OpenSSH)": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Private Key (PGP)": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9+/=_\-]{20,})['\"]?",
    "Password Assignment": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Database URL": r"(?:postgres|mysql|mongodb|redis)://[^@\s]+@[^\s]+",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
    "Authorization Header": r"(?i)authorization\s*[:=]\s*['\"]?\s*(?:bearer|basic|token)\s+[a-zA-Z0-9\-._~+/=]{10,}",
    "Telegram Bot Token": r"[0-9]+:[0-9a-zA-Z_-]{35}",
    "Discord Bot Token": r"[MN][0-9a-zA-Z_-]{23,25}\.[0-9a-zA-Z_-]{6}\.[0-9a-zA-Z_-]{27,}",
    "Twilio Token": r"SK[0-9a-fA-F]{32}",
    "NPM Token": r"npm_[0-9a-zA-Z]{36}",
    "SendGrid API Key": r"SG\.[0-9a-zA-Z_-]{22,}\.[0-9a-zA-Z_-]{22,}",
    "PayPal Secret": r"(?i)paypal.{0,20}(?:secret|client).{0,20}['\"]?([0-9a-zA-Z_-]{20,})['\"]?",
    "Generic Token": r"(?i)(?:token|secret|key)\s*[:=]\s*['\"]?([a-zA-Z0-9+/=_-]{32,})['\"]?",
}

# Low-confidence / informational patterns
MEDIUM_CONFIDENCE_PATTERNS = {
    "IP Address (private)": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Internal URL": r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|staging|dev|internal|test)[^\s]*",
    "Hardcoded Port": r"(?i)port\s*[:=]\s*['\"]?(\d{2,5})['\"]?",
}

# Directories and files to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".env", "dist", "build", ".next", ".nuxt", "target", "vendor",
    ".terraform", ".serverless", "coverage", ".cache", "tmp", ".pytest_cache",
    ".mypy_cache", ".tox", "bower_components", ".idea", ".vscode",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
    "poetry.lock", "Pipfile.lock", "Cargo.lock", "composer.lock",
    ".DS_Store", "Thumbs.db",
}

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".ttf", ".woff", ".woff2", ".eot",
    ".min.js", ".min.css",
    ".pyc", ".pyo",
}


def should_skip_path(filepath: Path, root: Path) -> bool:
    """Determine if a file should be skipped."""
    rel = filepath.relative_to(root)
    parts = rel.parts

    # Skip directories
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return True
        if part.startswith(".") and part not in (".github", ".well-known"):
            return True

    # Skip specific files
    if filepath.name in SKIP_FILES:
        return True

    # Skip by extension
    for ext in SKIP_EXTENSIONS:
        if filepath.name.endswith(ext):
            return True

    # Skip binary files
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            f.read(100)
    except (UnicodeDecodeError, IsADirectoryError, PermissionError):
        return True

    # Skip files over 1MB (usually not source code)
    try:
        if filepath.stat().st_size > 1_000_000:
            return True
    except OSError:
        return True

    return False


def mask_secret(value: str) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_file(filepath: Path, root: Path) -> list:
    """Scan a single file for secrets."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = content.split("\n")
    rel_path = str(filepath.relative_to(root))

    for pattern_name, pattern in HIGH_CONFIDENCE_PATTERNS.items():
        for match in re.finditer(pattern, content, re.MULTILINE):
            # Get the matched value
            matched = match.group(0)
            if len(match.groups()) > 0:
                matched = match.group(1) if match.group(1) else matched

            # Find line number
            pos = match.start()
            line_num = content[:pos].count("\n") + 1
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            # Skip common test/fixture patterns
            if any(skip in filepath.name.lower() for skip in ["test", "spec", "mock", "fixture", "example"]):
                continue

            # Skip if it looks like a placeholder
            if any(placeholder in matched.lower() for placeholder in
                   ["example", "placeholder", "your-key", "your_token", "xxx", "todo", "changeme"]):
                continue

            findings.append({
                "file": rel_path,
                "line": line_num,
                "pattern": pattern_name,
                "severity": "HIGH",
                "matched": mask_secret(matched),
                "context": line_content[:120] if len(line_content) > 120 else line_content,
            })

    for pattern_name, pattern in MEDIUM_CONFIDENCE_PATTERNS.items():
        for match in re.finditer(pattern, content, re.MULTILINE):
            pos = match.start()
            line_num = content[:pos].count("\n") + 1
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            if any(skip in filepath.name.lower() for skip in ["test", "spec", "mock", "fixture"]):
                continue

            matched = match.group(0)

            findings.append({
                "file": rel_path,
                "line": line_num,
                "pattern": pattern_name,
                "severity": "MEDIUM",
                "matched": mask_secret(matched),
                "context": line_content[:120] if len(line_content) > 120 else line_content,
            })

    return findings


def scan_directory(root: Path, extensions: set = None) -> dict:
    """Scan a directory recursively for secrets."""
    all_findings = []
    files_scanned = 0
    files_skipped = 0

    for filepath in root.rglob("*"):
        if not filepath.is_file():
            continue

        if should_skip_path(filepath, root):
            files_skipped += 1
            continue

        if extensions and filepath.suffix not in extensions:
            files_skipped += 1
            continue

        findings = scan_file(filepath, root)
        if findings:
            all_findings.extend(findings)
        files_scanned += 1

    # Deduplicate
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["file"], f["line"], f["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "findings": unique,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "total_findings": len(unique),
        "high_severity": sum(1 for f in unique if f["severity"] == "HIGH"),
        "medium_severity": sum(1 for f in unique if f["severity"] == "MEDIUM"),
    }


def generate_report(results: dict, root: str, output_format: str = "text"):
    """Generate a formatted report."""
    findings = results["findings"]

    if output_format == "json":
        return json.dumps({
            "scan_time": datetime.now().isoformat(),
            "target": str(root),
            "files_scanned": results["files_scanned"],
            "files_skipped": results["files_skipped"],
            "total_findings": results["total_findings"],
            "high_severity": results["high_severity"],
            "medium_severity": results["medium_severity"],
            "findings": findings,
        }, indent=2)

    # Text report
    lines = []
    lines.append("=" * 60)
    lines.append("  EnvGuard v{} — Secrets Scan Report".format(VERSION))
    lines.append("=" * 60)
    lines.append(f"  Target:       {root}")
    lines.append(f"  Scan time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Files scanned: {results['files_scanned']}")
    lines.append(f"  Files skipped: {results['files_skipped']}")
    lines.append(f"  Findings:      {results['total_findings']} "
                 f"(HIGH: {results['high_severity']}, MEDIUM: {results['medium_severity']})")
    lines.append("=" * 60)

    if not findings:
        lines.append("\n  ✅ No secrets found. Your codebase looks clean!\n")
        return "\n".join(lines)

    # Group by file
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    lines.append("")
    for filepath, file_findings in sorted(by_file.items()):
        lines.append(f"\n  📄 {filepath}")
        for f in sorted(file_findings, key=lambda x: x["line"]):
            icon = "🔴" if f["severity"] == "HIGH" else "🟡"
            lines.append(f"    {icon} Line {f['line']}: [{f['pattern']}]")
            lines.append(f"       Match: {f['matched']}")
            if f["context"]:
                lines.append(f"       Code:  {f['context']}")
            lines.append("")

    lines.append("=" * 60)
    lines.append("  ⚠️  ACTION REQUIRED")
    lines.append("  Review each finding carefully. Rotate any exposed keys immediately.")
    lines.append("  Use 'git filter-branch' or 'bfg-repo-cleaner' to purge from history.")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="EnvGuard — Scan codebases for exposed secrets and sensitive data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  envguard .                          # Scan current directory
  envguard /path/to/project           # Scan specific directory
  envguard . --json > report.json     # JSON output for CI/CD
  envguard . --ext .py,.js            # Only scan Python/JS files
  envguard . --strict                 # Only HIGH severity (no MEDIUM noise)
        """
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--strict", action="store_true", help="Only report HIGH severity findings")
    parser.add_argument("--ext", help="Comma-separated file extensions to scan (e.g. .py,.js,.ts)")
    parser.add_argument("--output", "-o", help="Write report to file")

    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: Path '{root}' does not exist.", file=sys.stderr)
        sys.exit(1)
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    extensions = None
    if args.ext:
        extensions = {ext.strip() if ext.startswith(".") else f".{ext.strip()}"
                      for ext in args.ext.split(",")}

    print(f"  EnvGuard v{VERSION} — scanning {root}...", file=sys.stderr)
    results = scan_directory(root, extensions)

    if args.strict:
        results["findings"] = [f for f in results["findings"] if f["severity"] == "HIGH"]
        results["total_findings"] = len(results["findings"])
        results["high_severity"] = results["total_findings"]
        results["medium_severity"] = 0

    output_format = "json" if args.json else "text"
    report = generate_report(results, str(root), output_format)

    if args.output:
        Path(args.output).write_text(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    # Exit with error if secrets found (for CI/CD)
    if results["high_severity"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()