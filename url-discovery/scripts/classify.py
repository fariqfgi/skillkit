#!/usr/bin/env python3 -I
"""
Classify and aggregate URL discovery results into a structured inventory.

Usage:
    python3 classify.py <urls_dedup.txt> <gf_matches.txt> <params.json> <output.json>
"""
import json
import sys
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Vulnerability class pattern → gf category
VUL_CLASSES = ["xss", "ssrf", "idor", "sqli", "redirect", "ssti", "lfi", "rce"]

# Interesting endpoint patterns (for prioritization)
HIGH_VALUE_RE = re.compile(
    r"/(api|v\d+|graphql|gql|rest|admin|internal|auth|login|oauth|sso|token|"
    r"refresh|session|register|upload|export|report|webhook|debug|actuator|"
    r"swagger|openapi|docs|backup|config|settings|manage|user|account|payment)",
    re.IGNORECASE,
)


def classify_url(url: str) -> dict:
    try:
        p = urlparse(url)
        path = p.path
        params = list(parse_qs(p.query).keys())
        return {
            "url": url,
            "path": path,
            "params": params,
            "has_params": len(params) > 0,
            "high_value": bool(HIGH_VALUE_RE.search(path)),
            "vuln_classes": [],
        }
    except Exception:
        return {"url": url, "path": "", "params": [], "has_params": False, "high_value": False, "vuln_classes": []}


def main():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <urls_dedup.txt> <gf_matches.txt> <params.json> <output.json>", file=sys.stderr)
        sys.exit(1)

    urls_file = Path(sys.argv[1])
    gf_file = Path(sys.argv[2])
    params_file = Path(sys.argv[3])
    out_file = Path(sys.argv[4])

    # Load all URLs
    urls = []
    if urls_file.exists():
        urls = [u.strip() for u in urls_file.read_text().splitlines() if u.strip()]

    # Load gf-matched URLs (those with vuln signals)
    gf_matches = set()
    if gf_file.exists():
        gf_matches = {u.strip() for u in gf_file.read_text().splitlines() if u.strip()}

    # Load param discovery results
    param_data = {}
    if params_file.exists():
        try:
            pd = json.loads(params_file.read_text())
            for entry in pd:
                u = entry.get("url", "")
                p = entry.get("params", [])
                if u and p:
                    param_data[u] = p
        except Exception:
            pass

    # Build inventory
    inventory = []
    high_value = []
    vuln_candidates = []

    for url in urls:
        entry = classify_url(url)

        # Mark vuln class
        if url in gf_matches:
            entry["vuln_classes"] = ["flagged"]  # detailed classes from per-file gf output

        # Inject discovered params
        if url in param_data:
            entry["discovered_params"] = param_data[url]

        inventory.append(entry)

        if entry["high_value"]:
            high_value.append(url)
        if entry["vuln_classes"] or entry.get("discovered_params"):
            vuln_candidates.append(url)

    summary = {
        "total_urls": len(inventory),
        "high_value_endpoints": len(high_value),
        "vuln_signal_urls": len(vuln_candidates),
        "urls_with_params": sum(1 for e in inventory if e["has_params"]),
        "param_discovery_hits": len(param_data),
    }

    output = {
        "summary": summary,
        "high_value_endpoints": high_value[:100],
        "vuln_candidates": vuln_candidates[:200],
        "full_inventory": inventory,
    }

    out_file.write_text(json.dumps(output, indent=2))

    print(f"[+] URL inventory written to {out_file}")
    print(f"    Total URLs:          {summary['total_urls']}")
    print(f"    High-value:          {summary['high_value_endpoints']}")
    print(f"    Vuln signals:        {summary['vuln_signal_urls']}")
    print(f"    URLs with params:    {summary['urls_with_params']}")
    print(f"    Param discovery hits:{summary['param_discovery_hits']}")


if __name__ == "__main__":
    main()
