#!/usr/bin/env python3 -I
"""
Parse httpx JSONL output and produce a structured inventory.json
grouped by interest tier for the subdomain-alive skill.

Usage:
    python3 triage.py httpx_raw.jsonl inventory.json
"""
import json
import re
import sys
from pathlib import Path


API_PATTERNS = re.compile(
    r"(/api[/v]|/graphql|/rest/|/swagger|/openapi|/v[0-9]+/|/ws/|/rpc[/.])",
    re.IGNORECASE,
)

INTERESTING_HEADERS = {
    "x-powered-by", "x-application", "x-backend", "x-upstream",
    "x-amz-", "x-goog-", "cf-ray", "x-envoy", "x-kong-",
    "www-authenticate", "x-debug", "x-frame-options",
}


def tier(entry: dict) -> str:
    status = entry.get("status_code", 0)
    title = (entry.get("title") or "").strip()
    tech = entry.get("technologies") or []
    url = entry.get("url", "")
    headers = {k.lower(): v for k, v in (entry.get("response_headers") or {}).items()}

    has_auth_header = "www-authenticate" in headers
    has_interesting_header = any(
        any(h.startswith(ih) for ih in INTERESTING_HEADERS) for h in headers
    )
    has_api_pattern = bool(API_PATTERNS.search(url))
    has_tech = bool(tech)
    no_title = not title or title in ("", "404", "403", "401", "Error")

    if status in (401, 403) or has_auth_header:
        return "T1"
    if status == 500:
        return "T1"
    if no_title and has_interesting_header:
        return "T1"
    if has_api_pattern:
        return "T1"
    if status == 200 and (has_tech or not no_title):
        return "T2"
    if status in (500, 503) and not has_auth_header:
        return "T2"
    if status in (301, 302):
        return "T3"
    if status == 200 and no_title:
        return "T3"
    return "T4"


def parse_entry(raw: dict) -> dict:
    technologies = []
    for key in ("technologies", "tech", "technology"):
        val = raw.get(key)
        if isinstance(val, list):
            technologies = [str(t) for t in val]
            break
        if isinstance(val, str) and val:
            technologies = [val]
            break

    return {
        "url": raw.get("url", ""),
        "host": raw.get("host", raw.get("input", "")),
        "status_code": raw.get("status_code", 0),
        "title": (raw.get("title") or "").strip(),
        "server": raw.get("webserver") or raw.get("server") or "",
        "tech": technologies,
        "cdn": raw.get("cdn_name") or raw.get("cdn") or "",
        "content_length": raw.get("content_length", 0),
        "ip": (raw.get("a") or [""])[0] if isinstance(raw.get("a"), list) else raw.get("ip", ""),
        "favicon_hash": raw.get("favicon_mmh3") or raw.get("favicon") or "",
        "redirect_location": raw.get("location") or "",
    }


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} httpx_raw.jsonl inventory.json", file=sys.stderr)
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not in_path.exists():
        print(f"[!] Input file not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    tiers: dict[str, list] = {"T1": [], "T2": [], "T3": [], "T4": []}
    seen_hosts: set[str] = set()

    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry = parse_entry(raw)
            host = entry["host"]
            if host in seen_hosts:
                continue
            seen_hosts.add(host)

            t = tier(entry)
            entry["tier"] = t
            tiers[t].append(entry)

    summary = {
        "total": sum(len(v) for v in tiers.values()),
        "T1_high": len(tiers["T1"]),
        "T2_medium": len(tiers["T2"]),
        "T3_low": len(tiers["T3"]),
        "T4_info": len(tiers["T4"]),
    }

    result = {"summary": summary, "tiers": tiers}

    with out_path.open("w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Inventory written to {out_path}")
    print(f"    T1 (high):   {summary['T1_high']}")
    print(f"    T2 (medium): {summary['T2_medium']}")
    print(f"    T3 (low):    {summary['T3_low']}")
    print(f"    T4 (info):   {summary['T4_info']}")


if __name__ == "__main__":
    main()
