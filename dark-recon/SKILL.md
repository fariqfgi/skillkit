---
name: dark-recon
description: Deep reconnaissance for subdomains that returned 401/403/500 or have no UI (blank title, no tech fingerprint). Probes ports, inspects headers, tries common paths, and detects hidden APIs or admin panels. Use on T1 subdomains from subdomain-alive before targeted exploitation.
compatibility: Bash, insert_assets, add_hint, task context.
---

# Dark Recon — Hidden Surface Discovery

Run on T1 subdomains from `subdomain-alive` — targets that responded but have no visible UI, returned 401/403/500, or showed interesting auth headers. A blank page or error on `/` often has active surface behind it.

## What to look for

| Signal | Interpretation |
|--------|---------------|
| 401 on `/` | Auth-gated resource — try different paths, methods, headers |
| 403 on `/` | IP/role restricted — may work from different vantage point, path bypass |
| 500 on `/` | Unhandled exception — stack trace, framework version, internal path |
| No title, responds | API server, internal service, webhook receiver |
| `WWW-Authenticate: Bearer` | JWT-protected API — enumerate endpoints |
| `X-Powered-By: internal-framework` | Internal tooling accidentally exposed |
| Open `/metrics` or `/actuator` | Spring Boot / Prometheus — info disclosure |
| Open `/api-docs` or `/swagger.json` | Self-documented API — instant surface map |

---

## Step 1 — Port Scan

Check for non-standard ports on the target IP:

```bash
TARGET_HOST="dark.target.com"
TARGET_IP=$(dig +short "$TARGET_HOST" | head -1)
OUTDIR="/tmp/dark-$TARGET_HOST"
mkdir -p "$OUTDIR"

# Fast port scan — top 1000 ports
naabu \
  -host "$TARGET_IP" \
  -top-ports 1000 \
  -silent \
  -json \
  -o "$OUTDIR/ports.jsonl" \
  2>/dev/null

echo "[+] Open ports:"
cat "$OUTDIR/ports.jsonl" | python3 -c "
import json, sys
for line in sys.stdin:
    d = json.loads(line.strip())
    print(f'  {d.get(\"port\", \"?\")} ({d.get(\"protocol\", \"tcp\")})')
"
```

For each additional open port found, probe with httpx:
```bash
# Example: port 8080 found
httpx -u "http://$TARGET_HOST:8080" \
  -status-code -title -tech-detect -web-server \
  -follow-redirects -silent -json 2>/dev/null
```

---

## Step 2 — Header Intelligence

Inspect full response headers — they reveal more than the body:

```bash
python3 skills/dark-recon/scripts/probe_headers.py \
  "$TARGET_HOST" \
  "$OUTDIR/headers.json"
```

Key headers to look for:
- `Server`: exact web server version (nginx/1.14.0 = check CVEs)
- `X-Powered-By`: framework fingerprint
- `WWW-Authenticate`: auth type (Bearer, Basic, Negotiate)
- `X-Debug-*`, `X-Internal-*`: debug mode indicators
- `Access-Control-Allow-Origin: *`: CORS wide-open
- `Content-Security-Policy`: reveals trusted domains (SSRF targets)
- `Link`: sometimes exposes API rel links
- `X-Runtime`, `X-Request-Id`: framework-specific (Rails, Django)

---

## Step 3 — Common Path Probe

Try standard paths that expose hidden functionality:

```bash
python3 skills/dark-recon/scripts/path_probe.py \
  "https://$TARGET_HOST" \
  "$OUTDIR/paths.json"
```

The script probes (one request at a time, 2s delay):

**API documentation**
- `/swagger.json`, `/swagger.yaml`, `/swagger/v1/swagger.json`
- `/openapi.json`, `/openapi.yaml`, `/api-docs`, `/api-docs/v1`
- `/v2/api-docs`, `/v3/api-docs`

**Health / metrics (common info leak)**
- `/health`, `/health/`, `/healthz`, `/ping`, `/status`, `/ready`
- `/metrics`, `/actuator`, `/actuator/health`, `/actuator/info`, `/actuator/env`
- `/actuator/mappings` (Spring Boot: full route list)
- `/__debug__`, `/debug`, `/debug/pprof` (Go pprof)

**Admin surfaces**
- `/admin`, `/admin/`, `/administrator`
- `/manage`, `/management`, `/console`
- `/_admin`, `/.admin`

**API versioning**
- `/api`, `/api/v1`, `/api/v2`, `/api/v3`
- `/v1`, `/v2`, `/rest`, `/graphql`, `/gql`

**Common files**
- `/robots.txt`, `/sitemap.xml`, `/.well-known/`
- `/.git/HEAD` (git exposure)
- `/config.json`, `/config.yml`, `/settings.json`
- `/.env` (environment exposure)

---

## Step 4 — Auth Bypass Probes

Only for 401/403 targets. Try these before any deeper testing:

```bash
# Method override
curl -sk -o /dev/null -w "%{http_code}" \
  -X POST "https://$TARGET_HOST/" \
  -H "X-HTTP-Method-Override: GET"

# Path traversal bypass (common nginx/WAF misconfig)
curl -sk -o /dev/null -w "%{http_code}" \
  "https://$TARGET_HOST/..;/"

# IP forwarding bypass
curl -sk -o /dev/null -w "%{http_code}" \
  "https://$TARGET_HOST/" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1"

# Content-Type bypass for API endpoints
curl -sk -o /dev/null -w "%{http_code}" \
  -X GET "https://$TARGET_HOST/api" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json"
```

**Stop and escalate** if any bypass returns 200 — that is a confirmed access control bypass, use evidence-confirmation skill.

---

## Step 5 — Save Findings

For each discovered surface:
- Open API spec found → `insert_assets` (kind: `app`) + `add_hint` for full URL
- Admin panel found → `add_hint` for priority follow-up
- Auth bypass confirmed → invoke `evidence-confirmation` skill
- Interesting headers → `add_hint` with raw headers and analysis

## Constraints

- Maximum 3 requests per path, 2 seconds between each
- Max 10 seconds timeout per request
- Do NOT brute-force paths (no wordlist scanning > 50 paths without explicit approval)
- Do NOT follow redirects to out-of-scope domains
- Do NOT modify state — GET and HEAD requests only, unless a bypass test specifically requires POST
- Capture raw request/response for every successful (non-expected-denial) finding
- Stop immediately on rate-limit (429) — wait 60 seconds before resuming, max 2 retries
