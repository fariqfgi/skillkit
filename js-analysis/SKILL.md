---
name: js-analysis
description: Discover and analyze JavaScript files from alive subdomains. Extracts API endpoints, authentication routes, hardcoded secrets/keys, internal hostnames, and hidden features. Use after subdomain-alive for Bug Bounty or pentest JS surface mapping.
compatibility: Bash, insert_assets, add_hint, task context.
---

# JavaScript File Analysis

Run after `subdomain-alive` has produced an alive host inventory. Focuses on extracting attack-surface intelligence from JS files — the most consistently underexplored source in bug bounty.

## What JS files reveal

| Finding type | Examples | Attack surface |
|---|---|---|
| API endpoints | `/api/v2/users`, `/internal/admin` | IDOR, auth bypass, undocumented APIs |
| Auth routes | `/oauth/token`, `/sso/callback`, `/api/auth` | Auth flow analysis |
| Hardcoded secrets | `apiKey=`, `Bearer `, AWS keys, JWT secrets | Direct exploitation |
| Internal hostnames | `api-internal.corp`, `10.0.0.1` | SSRF, internal pivot |
| Feature flags | `isAdmin`, `debugMode`, `betaFeature` | Logic bypass |
| GraphQL schemas | `__typename`, `mutation`, `subscription` | GraphQL introspection |

---

## Step 1 — Collect JS URLs (multi-source)

For each target host from inventory T1/T2:

```bash
TARGET_HOST="app.target.com"
OUTDIR="/tmp/js-$TARGET_HOST"
mkdir -p "$OUTDIR"

# Source 1: katana crawl with JS parsing enabled
katana \
  -u "https://$TARGET_HOST" \
  -d 5 \
  -jc \
  -jsl \
  -kf all \
  -ef css,png,jpg,gif,svg,ico,woff,woff2,ttf,eot \
  -silent \
  -o "$OUTDIR/katana_urls.txt" \
  2>/dev/null

# Source 2: gau (wayback machine + AlienVault OTX + Common Crawl)
gau "$TARGET_HOST" \
  --subs \
  --threads 5 \
  2>/dev/null | grep "\.js" | grep -v "\.json" | anew "$OUTDIR/js_urls.txt"

# Source 3: waybackurls
waybackurls "$TARGET_HOST" 2>/dev/null | grep "\.js" | grep -v "\.json" | anew "$OUTDIR/js_urls.txt"

# Merge katana results
grep "\.js" "$OUTDIR/katana_urls.txt" 2>/dev/null | grep -v "\.json" | anew "$OUTDIR/js_urls.txt"

echo "[+] Unique JS URLs: $(wc -l < $OUTDIR/js_urls.txt)"
```

---

## Step 2 — Download JS Files

```bash
# Filter to alive JS files with httpx, then download
httpx \
  -l "$OUTDIR/js_urls.txt" \
  -mc 200 \
  -silent \
  -o "$OUTDIR/js_alive.txt" \
  2>/dev/null

mkdir -p "$OUTDIR/files"
python3 skills/js-analysis/scripts/download_js.py \
  "$OUTDIR/js_alive.txt" \
  "$OUTDIR/files/" \
  --max-files 200 \
  --max-size-kb 2048
```

---

## Step 3 — Extract Intelligence

Run the bundled extractor on all downloaded files:

```bash
python3 skills/js-analysis/scripts/extract.py \
  "$OUTDIR/files/" \
  "$OUTDIR/findings.json" \
  --host "$TARGET_HOST"
```

Also run linkfinder for endpoint extraction:
```bash
for f in "$OUTDIR/files/"*.js; do
  linkfinder -i "$f" -o cli 2>/dev/null
done | sort -u | anew "$OUTDIR/linkfinder_endpoints.txt"
```

---

## Step 4 — Secret Scanning

```bash
# trufflehog on the JS files directory
trufflehog filesystem "$OUTDIR/files/" \
  --json \
  --no-update \
  2>/dev/null > "$OUTDIR/secrets.jsonl"

echo "[+] Secret scan results: $(wc -l < $OUTDIR/secrets.jsonl) potential findings"
```

---

## Step 5 — Review and Save

Review `findings.json` for:

1. **Endpoints not visible in the main app** → `insert_assets` (kind: `app`, with prop `source: js_analysis`)
2. **Hardcoded credentials or API keys** → `report_finding` (severity: high/critical)
3. **Internal hostnames/IPs** → `insert_assets` (kind: `service`) + note as SSRF candidate
4. **Interesting auth routes** → add to task hints for follow-up auth testing

### Severity guide for JS findings

| Finding | Severity |
|---|---|
| AWS secret key / private key | critical |
| Hardcoded auth token / bearer token in prod JS | high |
| Internal IP / hostname disclosure | medium |
| API endpoint not documented | info → investigate further |
| Debug/admin endpoint in prod | medium-high depending on exposure |

---

## Constraints

- Do NOT execute any extracted endpoints automatically — this skill is discovery only
- Do NOT store raw JS file content in findings/hints — summarize what was found
- Limit: max 200 JS files per host, max 2MB per file
- Skip minified files larger than 1MB (too expensive to parse, marginal return)
- If trufflehog finds secrets: verify they are live before reporting (call the API to confirm validity)
- Do not download from out-of-scope domains even if a JS file references them
