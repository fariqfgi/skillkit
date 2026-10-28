#!/usr/bin/env python3 -I
"""
Extract attack-surface intelligence from downloaded JavaScript files.

Finds: API endpoints, auth routes, hardcoded secrets, internal hostnames,
feature flags, GraphQL indicators, and suspicious strings.

Usage:
    python3 extract.py <js_dir> <findings.json> [--host target.com]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

# --- Patterns ---

ENDPOINT_RE = re.compile(
    r"""['"`](\/(api|v\d+|graphql|rest|admin|internal|auth|oauth|sso|user|account|payment|webhook|ws|rpc|backend|service)[^\s'"`<>{}\[\]]{0,120})['"`]""",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    ("aws_access_key",    re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("aws_secret_key",    re.compile(r"""['"`]([A-Za-z0-9/+]{40})['"`]""")),
    ("github_token",      re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})")),
    ("slack_token",       re.compile(r"(xox[baprs]-[A-Za-z0-9-]{10,})")),
    ("jwt_secret",        re.compile(r"""(?:jwt[_\-]?secret|jwtSecret)\s*[:=]\s*['"`]([^'"`]{8,})['"`]""", re.IGNORECASE)),
    ("bearer_hardcoded",  re.compile(r"""['"`](Bearer\s+[A-Za-z0-9\-._~+/]{20,})['"`]""", re.IGNORECASE)),
    ("api_key_generic",   re.compile(r"""(?:api[_\-]?key|apiKey|api_token|access_token)\s*[:=]\s*['"`]([A-Za-z0-9\-_]{16,})['"`]""", re.IGNORECASE)),
    ("google_api_key",    re.compile(r"(AIza[0-9A-Za-z\-_]{35})")),
    ("private_key_pem",   re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("stripe_key",        re.compile(r"(sk_live_[A-Za-z0-9]{24,})")),
    ("sendgrid_key",      re.compile(r"(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})")),
    ("twilio_token",      re.compile(r"(SK[0-9a-f]{32})")),
]

INTERNAL_HOST_RE = re.compile(
    r"""['"`]((?:[a-z0-9\-]+\.){1,5}(?:internal|corp|local|intranet|staging|dev|test|qa|prod|backend|svc|service|cluster\.local)[^'"`\s]{0,40})['"`]""",
    re.IGNORECASE,
)

INTERNAL_IP_RE = re.compile(
    r"""['"`]((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))['"`]"""
)

GRAPHQL_RE = re.compile(r"(gql`|graphql|__typename|subscription\s*\{|mutation\s*\{|query\s*\{)", re.IGNORECASE)

DEBUG_RE = re.compile(
    r"""(?:debugMode|isAdmin|adminPanel|IS_DEBUG|ENABLE_DEBUG|showDevTools|bypassAuth)\s*[:=]\s*(true|1)""",
    re.IGNORECASE,
)


def extract_from_file(path: Path, host: str) -> dict:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"file": str(path.name), "error": str(e)}

    findings = {
        "file": path.name,
        "size_kb": round(path.stat().st_size / 1024, 1),
        "endpoints": [],
        "secrets": [],
        "internal_hosts": [],
        "graphql": False,
        "debug_flags": [],
    }

    # Endpoints
    seen_ep = set()
    for m in ENDPOINT_RE.finditer(content):
        ep = m.group(1)
        if ep not in seen_ep and len(ep) > 3:
            seen_ep.add(ep)
            findings["endpoints"].append(ep)

    # Secrets
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group(1) if m.lastindex else m.group(0)
            # Rough false-positive filter: skip if looks like a placeholder
            if any(x in val.lower() for x in ("example", "placeholder", "your_", "xxx", "yyy", "test")):
                continue
            findings["secrets"].append({
                "type": name,
                "value_preview": val[:12] + "..." if len(val) > 12 else val,
                "line": content[:m.start()].count("\n") + 1,
            })

    # Internal hosts
    seen_ih = set()
    for m in INTERNAL_HOST_RE.finditer(content):
        h = m.group(1).lower()
        if h not in seen_ih and host not in h:
            seen_ih.add(h)
            findings["internal_hosts"].append(h)
    for m in INTERNAL_IP_RE.finditer(content):
        ip = m.group(1)
        if ip not in seen_ih:
            seen_ih.add(ip)
            findings["internal_hosts"].append(ip)

    # GraphQL
    findings["graphql"] = bool(GRAPHQL_RE.search(content))

    # Debug flags
    for m in DEBUG_RE.finditer(content):
        findings["debug_flags"].append(m.group(0)[:80])

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("js_dir")
    parser.add_argument("output")
    parser.add_argument("--host", default="")
    args = parser.parse_args()

    js_dir = Path(args.js_dir)
    if not js_dir.is_dir():
        print(f"[!] Directory not found: {js_dir}", file=sys.stderr)
        sys.exit(1)

    js_files = sorted(js_dir.glob("*.js"))
    if not js_files:
        print(f"[!] No .js files in {js_dir}", file=sys.stderr)
        sys.exit(0)

    results = []
    all_endpoints: set[str] = set()
    all_secrets = []
    all_internal = set()

    for f in js_files:
        r = extract_from_file(f, args.host)
        results.append(r)
        all_endpoints.update(r.get("endpoints", []))
        all_secrets.extend(r.get("secrets", []))
        all_internal.update(r.get("internal_hosts", []))

    summary = {
        "files_analyzed": len(results),
        "unique_endpoints": len(all_endpoints),
        "secrets_found": len(all_secrets),
        "internal_hosts": len(all_internal),
        "graphql_files": sum(1 for r in results if r.get("graphql")),
    }

    output = {
        "host": args.host,
        "summary": summary,
        "all_endpoints": sorted(all_endpoints),
        "all_secrets": all_secrets,
        "all_internal_hosts": sorted(all_internal),
        "per_file": results,
    }

    Path(args.output).write_text(json.dumps(output, indent=2))
    print(f"[+] Findings written to {args.output}")
    print(f"    Files analyzed:   {summary['files_analyzed']}")
    print(f"    Unique endpoints: {summary['unique_endpoints']}")
    print(f"    Secrets found:    {summary['secrets_found']}")
    print(f"    Internal hosts:   {summary['internal_hosts']}")
    print(f"    GraphQL files:    {summary['graphql_files']}")


if __name__ == "__main__":
    main()
