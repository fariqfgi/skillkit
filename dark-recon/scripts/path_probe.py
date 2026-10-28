#!/usr/bin/env python3 -I
"""
Probe common paths on a target URL for hidden APIs, admin panels, and info leaks.
Rate-limited: 2 seconds between requests.

Usage:
    python3 path_probe.py <base_url> <output.json>
"""
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

PROBE_PATHS = [
    # API documentation
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/v1",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    # Health / metrics
    "/health",
    "/healthz",
    "/health/",
    "/ping",
    "/status",
    "/ready",
    "/live",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/__debug__",
    "/debug",
    "/debug/pprof",
    "/debug/vars",
    # Admin surfaces
    "/admin",
    "/admin/",
    "/administrator",
    "/manage",
    "/management",
    "/console",
    "/_admin",
    # API versioning
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/rest",
    "/graphql",
    "/gql",
    # Common files
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/config.json",
    "/config.yml",
    "/settings.json",
    "/.env",
    "/env",
    "/server-status",
    "/server-info",
    # Internal/debug
    "/info",
    "/version",
    "/_version",
    "/build",
    "/_health",
    "/_status",
]

# Status codes that indicate something interesting exists
INTERESTING_CODES = {200, 401, 403, 500, 503}
# Expected denial (not interesting unless combined with interesting headers)
DENIAL_CODES = {404, 410}


def probe_path(base_url: str, path: str, timeout: int = 10) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; security-researcher/1.0)",
                "Accept": "application/json, text/html, */*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_preview = resp.read(512).decode("utf-8", errors="replace")
            return {
                "url": url,
                "path": path,
                "status": resp.status,
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": int(resp.headers.get("Content-Length", 0) or 0),
                "body_preview": body_preview[:200],
                "interesting": resp.status in INTERESTING_CODES,
            }
    except urllib.error.HTTPError as e:
        body_preview = ""
        try:
            body_preview = e.read(512).decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        return {
            "url": url,
            "path": path,
            "status": e.code,
            "content_type": e.headers.get("Content-Type", ""),
            "content_length": 0,
            "body_preview": body_preview,
            "interesting": e.code in INTERESTING_CODES,
        }
    except Exception:
        return None


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <base_url> <output.json>", file=sys.stderr)
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    out_path = Path(sys.argv[2])

    results = []
    interesting = []

    for path in PROBE_PATHS:
        result = probe_path(base_url, path)
        if result:
            results.append(result)
            if result["interesting"]:
                interesting.append(result)
                print(f"  [!] {result['status']} {path}", file=sys.stderr)
                if result["body_preview"]:
                    preview = result["body_preview"].replace("\n", " ")[:80]
                    print(f"      Preview: {preview}", file=sys.stderr)
            else:
                print(f"  [ ] {result['status']} {path}", file=sys.stderr)
        time.sleep(2)

    output = {
        "base_url": base_url,
        "total_probed": len(results),
        "interesting_count": len(interesting),
        "interesting": interesting,
        "all_results": results,
    }

    out_path.write_text(json.dumps(output, indent=2))
    print(f"\n[+] Results written to {out_path}", file=sys.stderr)
    print(f"    Interesting paths: {len(interesting)}", file=sys.stderr)


if __name__ == "__main__":
    main()
