---
name: subdomain-alive
description: Enumerate subdomains for a wildcard scope, resolve DNS, probe all alive hosts (200/301/302/401/403/500/503 — anything that responds), and fingerprint each one (title, tech stack, server, CDN/WAF). Use at the start of every wildcard bug bounty or pentest engagement before any targeted testing.
compatibility: Bash, insert_assets, task context.
---

# Subdomain Enumeration + Alive Check + Fingerprinting

Full pipeline for wildcard scope reconnaissance. Always run this before targeted testing.

## Why include 401/403/500?

- **401/403**: resource exists and is protected — worth probing auth bypass, different HTTP methods, path traversal
- **500**: server error on root path — often stack trace, framework version, internal path disclosure
- **503**: staging/maintenance mode — sometimes returns debug info or bypasses with `X-Forwarded-For`
- Skip nothing that responds. A blank page or error on `/` might have interesting API endpoints behind it.

---

## Step 1 — Subdomain Enumeration (passive, multi-source)

Run all sources concurrently and merge via `anew`:

```bash
# Active domain: target.com (wildcard scope *.target.com)
TARGET="target.com"
OUTDIR="/tmp/recon-$TARGET"
mkdir -p "$OUTDIR"

# Source 1: subfinder (passive, multi-provider)
subfinder -d "$TARGET" -silent -all -rl 10 2>/dev/null | anew "$OUTDIR/subs_raw.txt"

# Source 2: assetfinder
assetfinder --subs-only "$TARGET" 2>/dev/null | anew "$OUTDIR/subs_raw.txt"

# Source 3: CT logs via skill ct-subs (certspotter + crt.sh)
python3 skills/ct-subs/scripts/ct_subs.py "$TARGET" -o "$OUTDIR/ct_subs.json"
python3 -c "
import json, sys
data = json.load(open('$OUTDIR/ct_subs.json'))
for domain, subs in data.items():
    for s in subs: print(s)
" | anew "$OUTDIR/subs_raw.txt"

echo "[+] Total unique subdomains: $(wc -l < $OUTDIR/subs_raw.txt)"
```

---

## Step 2 — DNS Resolution

Filter to only resolvable subdomains:

```bash
dnsx -l "$OUTDIR/subs_raw.txt" -silent -a -resp -t 20 -rl 50 -o "$OUTDIR/subs_resolved.txt" 2>/dev/null
# subs_resolved.txt format: subdomain [IP]
# Extract just the hostnames for httpx:
cut -d' ' -f1 "$OUTDIR/subs_resolved.txt" > "$OUTDIR/subs_alive_dns.txt"
echo "[+] DNS-resolved: $(wc -l < $OUTDIR/subs_alive_dns.txt)"
```

---

## Step 3 — HTTP Probe (broad status filter)

Include ALL responding hosts — do NOT filter to 200 only:

```bash
httpx \
  -l "$OUTDIR/subs_alive_dns.txt" \
  -status-code -title -tech-detect -web-server \
  -follow-redirects \
  -favicon \
  -cdn \
  -content-length \
  -threads 20 \
  -timeout 10 \
  -json \
  -o "$OUTDIR/httpx_raw.jsonl" \
  -silent 2>/dev/null

echo "[+] Probed. Alive count: $(wc -l < $OUTDIR/httpx_raw.jsonl)"
```

---

## Step 4 — Parse and Triage

Run the bundled triage script to produce a structured inventory:

```bash
python3 skills/subdomain-alive/scripts/triage.py \
  "$OUTDIR/httpx_raw.jsonl" \
  "$OUTDIR/inventory.json"
```

The script produces `inventory.json` with entries grouped by interest tier:

| Tier | Criteria | Why interesting |
|------|----------|-----------------|
| **T1 — High** | 401/403 (auth-gated), no-title with open ports, API patterns in URL/header | Hidden resource, auth bypass candidate |
| **T2 — Medium** | 200 with tech fingerprint, 500 error | Active surface, error disclosure |
| **T3 — Low** | 301/302 redirect, CDN-only | Track destination, may expose internal |
| **T4 — Info** | NXDOMAIN after retry, timeout | Record as unresolved |

---

## Step 5 — Save to Asset Graph

```bash
python3 skills/subdomain-alive/scripts/save_assets.py \
  "$OUTDIR/inventory.json" \
  --task-id "$TASK_ID"
```

Use `insert_assets` for each T1/T2 subdomain with props:
- `status_code`, `title`, `tech`, `server`, `cdn`, `content_length`, `ip`, `tier`

---

## Output contract

The agent must save to the exploration graph before closing the intent:
1. Every alive subdomain → `insert_assets` (kind: `subdomain`)
2. T1/T2 subdomains → add props with full fingerprint
3. Note T1 targets as high-priority for follow-up intents: dark-recon or js-analysis

## Constraints

- Passive sources only in Step 1 — no brute-force wordlist DNS unless explicitly authorized
- Max 20 concurrent httpx threads — do not increase without explicit approval
- Do not follow redirects more than 3 hops
- Do not store response bodies — titles and headers only
- Stay within authorized scope: do not probe IPs outside the target's ASN unless confirmed related
