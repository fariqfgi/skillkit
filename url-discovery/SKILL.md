---
name: url-discovery
description: Full URL enumeration for a live subdomain. Combines passive (gau, waybackurls) and active (katana crawler) sources, deduplicates with uro, discovers hidden parameters (arjun), and classifies URLs by vulnerability class using gf patterns. Run after subdomain-alive on any T1/T2 subdomain.
compatibility: Bash, insert_assets, add_hint, task context.
---

# URL Discovery — Full Surface Enumeration

Run on T1/T2 subdomains after `subdomain-alive`. Goal: build a complete URL inventory with vulnerability-class tags that the planner can route to targeted testers.

## Input

- `TARGET` — the subdomain (e.g. `api.target.com`)
- `BASE_DOMAIN` — root domain (e.g. `target.com`) for scope guard
- `OUTDIR` — working directory (e.g. `/tmp/url-$TARGET`)

---

## Step 1 — Passive URL harvest

Pull archived URLs from multiple sources and merge:

```bash
TARGET="api.target.com"
BASE_DOMAIN="target.com"
OUTDIR="/tmp/url-$TARGET"
mkdir -p "$OUTDIR"

# gau: Common Crawl + Wayback Machine + OTX
gau --subs "$TARGET" \
    --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,pdf \
    --o "$OUTDIR/gau.txt" \
    2>/dev/null

# waybackurls: focused Wayback pull
echo "$TARGET" | waybackurls 2>/dev/null \
    | grep -v '\.\(png\|jpg\|jpeg\|gif\|svg\|ico\|css\|woff\|ttf\|eot\|pdf\)$' \
    > "$OUTDIR/wayback.txt"

# Merge and filter to in-scope only
cat "$OUTDIR/gau.txt" "$OUTDIR/wayback.txt" 2>/dev/null \
    | grep "$BASE_DOMAIN" \
    | sort -u \
    > "$OUTDIR/passive_urls.txt"

echo "[+] Passive URLs: $(wc -l < "$OUTDIR/passive_urls.txt")"
```

---

## Step 2 — Active crawl with katana

Katana discovers URLs the passive sources don't have (JS-rendered routes, new endpoints):

```bash
katana \
    -u "https://$TARGET" \
    -depth 3 \
    -jc \
    -jsl \
    -aff \
    -silent \
    -o "$OUTDIR/katana.txt" \
    -ignore-query-params \
    -timeout 20 \
    2>/dev/null

echo "[+] Katana URLs: $(wc -l < "$OUTDIR/katana.txt" 2>/dev/null || echo 0)"
```

---

## Step 3 — Merge and deduplicate

Use `uro` to remove redundant parameter variations and keep canonical URLs:

```bash
# Merge all sources
cat "$OUTDIR/passive_urls.txt" "$OUTDIR/katana.txt" 2>/dev/null \
    | grep "$BASE_DOMAIN" \
    | sort -u \
    > "$OUTDIR/all_urls_raw.txt"

# Deduplicate with uro (keeps unique path/parameter structure)
cat "$OUTDIR/all_urls_raw.txt" \
    | uro \
    > "$OUTDIR/urls_dedup.txt" 2>/dev/null \
    || cp "$OUTDIR/all_urls_raw.txt" "$OUTDIR/urls_dedup.txt"

echo "[+] After dedup: $(wc -l < "$OUTDIR/urls_dedup.txt") unique URLs"
```

---

## Step 4 — gf classification

Tag URLs by vulnerability class using gf pattern library:

```bash
for pattern in xss ssrf idor sqli redirect ssti lfi rce; do
    gf "$pattern" "$OUTDIR/urls_dedup.txt" > "$OUTDIR/gf_$pattern.txt" 2>/dev/null
    count=$(wc -l < "$OUTDIR/gf_$pattern.txt" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        echo "[!] $pattern: $count URLs"
    fi
done

# Aggregate: URLs that matched at least one pattern
cat "$OUTDIR/gf_"*.txt 2>/dev/null | sort -u > "$OUTDIR/gf_all_matches.txt"
echo "[+] Total URLs with vuln signals: $(wc -l < "$OUTDIR/gf_all_matches.txt")"
```

---

## Step 5 — Parameter discovery on key endpoints

For high-value endpoints (API paths, form handlers, search, auth), discover hidden parameters:

```bash
# Identify API / form endpoints from dedup list
grep -iE '(api|v[0-9]+|graphql|search|query|filter|user|account|admin|auth|login|register|upload|export|report)' \
    "$OUTDIR/urls_dedup.txt" \
    | head -30 \
    > "$OUTDIR/endpoints_for_param_discovery.txt"

# arjun: parameter miner (rate-limited — one endpoint at a time)
while IFS= read -r url; do
    arjun \
        -u "$url" \
        --stable \
        -q \
        -oJ "$OUTDIR/arjun_$(echo "$url" | md5sum | cut -c1-8).json" \
        2>/dev/null
    sleep 3
done < "$OUTDIR/endpoints_for_param_discovery.txt"

# Collect all discovered params
python3 -I -c "
import json, glob, sys

results = []
for f in glob.glob('$OUTDIR/arjun_*.json'):
    try:
        d = json.load(open(f))
        if isinstance(d, list):
            for r in d:
                if r.get('params'):
                    results.append({'url': r.get('url'), 'params': r['params']})
        elif d.get('params'):
            results.append({'url': d.get('url'), 'params': d['params']})
    except Exception:
        pass

print(json.dumps(results, indent=2))
" > "$OUTDIR/params_discovered.json"

echo "[+] Param discovery complete — $(python3 -I -c "import json; d=json.load(open('$OUTDIR/params_discovered.json')); print(sum(len(r.get('params',[])) for r in d))" 2>/dev/null || echo 0) parameters found"
```

---

## Step 6 — Classify and save results

```bash
python3 -I skills/url-discovery/scripts/classify.py \
    "$OUTDIR/urls_dedup.txt" \
    "$OUTDIR/gf_all_matches.txt" \
    "$OUTDIR/params_discovered.json" \
    "$OUTDIR/url_inventory.json"
```

---

## Step 7 — Register findings

For each vulnerability class with hits:

```bash
# Add as a task hint for each class with URLs
for pattern in xss ssrf idor sqli redirect ssti lfi; do
    count=$(wc -l < "$OUTDIR/gf_$pattern.txt" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        echo "URL class: $pattern — $count candidates on $TARGET"
        # Use add_hint or insert_assets to record the finding
    fi
done

# Insert full inventory as asset
# insert_assets kind=note title="URL Inventory: $TARGET" content="$(cat $OUTDIR/url_inventory.json)"
```

---

## Constraints

- Do NOT fuzz or inject — discovery only
- 3-second delay between arjun probes
- Skip URLs outside `$BASE_DOMAIN`
- Katana depth max 3 — do not increase without explicit approval
- Maximum 30 endpoints for arjun (API rate limit concern)
- Log every tool run to stderr, do not suppress errors silently
- gf requires `gf` binary + patterns in `~/.gf/` — skip gracefully if absent

## Tools Required

| Tool | Purpose |
|------|---------|
| `gau` | Passive URL archive (Common Crawl + Wayback + OTX) |
| `waybackurls` | Focused Wayback Machine pull |
| `katana` | Active JS-aware crawl |
| `uro` | URL deduplication (removes param noise) |
| `gf` | Pattern-based URL classification |
| `arjun` | Hidden parameter discovery |
