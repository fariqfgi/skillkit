#!/usr/bin/env python3 -I
"""
Probe a host's HTTP response headers and extract attack-surface intelligence.

Usage:
    python3 probe_headers.py <host> <output.json>
"""
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

INTERESTING_HEADERS = {
    "server", "x-powered-by", "x-runtime", "x-request-id",
    "www-authenticate", "access-control-allow-origin",
    "access-control-allow-methods", "access-control-allow-headers",
    "content-security-policy", "x-frame-options",
    "strict-transport-security", "x-debug", "x-internal",
    "x-backend", "x-upstream", "x-envoy-upstream-service-time",
    "x-kong-proxy-latency", "via", "link", "location",
    "set-cookie", "x-amz-request-id", "x-amz-id-2",
    "x-goog-request-id", "x-cloud-trace-context",
}

PROBES = [
    ("https", 443),
    ("http", 80),
    ("https", 8443),
    ("http", 8080),
]


def probe_url(url: str, timeout: int = 10) -> dict | None:
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; security-researcher/1.0)",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            return {
                "url": url,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in headers.items()},
                "content_length": int(headers.get("Content-Length", 0) or 0),
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "status": e.code,
            "headers": {k.lower(): v for k, v in dict(e.headers).items()},
            "content_length": 0,
        }
    except Exception:
        return None


def analyze(result: dict) -> dict:
    headers = result.get("headers", {})
    analysis = {
        "interesting_headers": {},
        "signals": [],
        "cors_wide_open": False,
        "auth_type": None,
    }

    for h in INTERESTING_HEADERS:
        if h in headers:
            analysis["interesting_headers"][h] = headers[h]

    # CORS
    origin = headers.get("access-control-allow-origin", "")
    if origin in ("*", "null"):
        analysis["cors_wide_open"] = True
        analysis["signals"].append(f"CORS: Access-Control-Allow-Origin: {origin}")

    # Auth
    www_auth = headers.get("www-authenticate", "")
    if www_auth:
        analysis["auth_type"] = www_auth.split(" ")[0]
        analysis["signals"].append(f"Auth required: {www_auth[:80]}")

    # Server version
    server = headers.get("server", "")
    if server:
        analysis["signals"].append(f"Server: {server}")

    # Framework
    xpb = headers.get("x-powered-by", "")
    if xpb:
        analysis["signals"].append(f"Framework: {xpb}")

    # CSP reveals trusted domains
    csp = headers.get("content-security-policy", "")
    if csp:
        analysis["signals"].append(f"CSP present (check for trusted domains): {csp[:120]}")

    # Debug indicators
    for h, v in headers.items():
        if "debug" in h or "internal" in h:
            analysis["signals"].append(f"Debug/internal header: {h}: {v}")

    return analysis


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <output.json>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1].strip().rstrip("/")
    out_path = Path(sys.argv[2])

    if host.startswith("http"):
        probes = [host]
    else:
        probes = [f"{scheme}://{host}:{port}" for scheme, port in PROBES]

    results = []
    for url in probes:
        print(f"[*] Probing {url} ...", file=sys.stderr)
        r = probe_url(url)
        if r:
            r["analysis"] = analyze(r)
            results.append(r)
            print(f"    Status: {r['status']}", file=sys.stderr)
            for sig in r["analysis"]["signals"]:
                print(f"    ! {sig}", file=sys.stderr)
        time.sleep(1)

    out_path.write_text(json.dumps({"host": host, "probes": results}, indent=2))
    print(f"[+] Headers written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
