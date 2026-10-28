---
name: port-scan
description: Fast port discovery and service fingerprinting. naabu for speed (top-1000 ports), nmap for service/version detection on discovered ports only. Produces a structured service map per host. Run once per in-scope IP range or subdomain IP to find non-standard attack surfaces.
compatibility: Bash, insert_assets, add_hint, task context.
---

# Port Scan — Service Discovery

Two-phase approach: naabu for breadth (fast, low latency), nmap for depth (version + script on confirmed open ports only). This avoids nmap's slow full-port scan while still getting service fingerprints.

## Input

- `TARGET` — hostname or IP (e.g. `api.target.com` or `10.0.0.5`)
- `SCOPE_CIDR` — optional CIDR range if scanning a subnet (e.g. `10.10.0.0/24`)
- `OUTDIR` — working directory

---

## Step 1 — Resolve target IP

```bash
TARGET="api.target.com"
OUTDIR="/tmp/portscan-$TARGET"
mkdir -p "$OUTDIR"

# Resolve hostname → IP (skip if already an IP)
if echo "$TARGET" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
    TARGET_IP="$TARGET"
else
    TARGET_IP=$(dig +short "$TARGET" | grep -E '^\d' | head -1)
fi

echo "[+] Target: $TARGET ($TARGET_IP)"
echo "$TARGET_IP" > "$OUTDIR/target_ip.txt"
```

---

## Step 2 — Fast port discovery with naabu

```bash
# Phase 1: top-1000 ports (fast baseline)
naabu \
    -host "$TARGET_IP" \
    -top-ports 1000 \
    -rate 100 \
    -timeout 5 \
    -silent \
    -json \
    -o "$OUTDIR/naabu_top1000.jsonl" \
    2>/dev/null

# Parse open ports
OPEN_PORTS=$(python3 -I -c "
import json, sys
ports = []
with open('$OUTDIR/naabu_top1000.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            ports.append(str(d.get('port', '')))
        except Exception:
            pass
print(','.join(sorted(set(ports), key=int)))
" 2>/dev/null)

echo "[+] Open ports (top-1000): $OPEN_PORTS"
echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"
```

Optional — extended scan on web services (check non-standard web ports):
```bash
# Phase 2: web-service-adjacent ports if no hit on 80/443
echo "$OPEN_PORTS" | grep -qE '(80|443|8080|8443)' || \
naabu \
    -host "$TARGET_IP" \
    -p 8000-9999,3000,3001,4000,4001,4200,5000,5001,7000,7001,8080-8090,8443,8888,9000,9090,9200,9300 \
    -rate 100 \
    -timeout 5 \
    -silent \
    -json \
    -o "$OUTDIR/naabu_web_extras.jsonl" \
    2>/dev/null

EXTRA_PORTS=$(python3 -I -c "
import json
ports = []
try:
    with open('$OUTDIR/naabu_web_extras.jsonl') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            d = json.loads(line)
            ports.append(str(d.get('port','')))
except FileNotFoundError:
    pass
print(','.join(sorted(set(ports), key=int)))
" 2>/dev/null)

[ -n "$EXTRA_PORTS" ] && {
    echo "[+] Extra web ports: $EXTRA_PORTS"
    OPEN_PORTS="${OPEN_PORTS},${EXTRA_PORTS}"
}
```

---

## Step 3 — Service fingerprint with nmap

Run nmap only on the ports naabu confirmed open — much faster than full nmap:

```bash
if [ -n "$OPEN_PORTS" ]; then
    nmap \
        -sV \
        --version-intensity 5 \
        -sC \
        -p "$OPEN_PORTS" \
        -T3 \
        --open \
        -oX "$OUTDIR/nmap_services.xml" \
        -oN "$OUTDIR/nmap_services.txt" \
        "$TARGET_IP" \
        2>/dev/null

    echo "[+] nmap service detection complete"
    grep -E '(open|filtered)' "$OUTDIR/nmap_services.txt"
else
    echo "[ ] No open ports — skipping nmap"
fi
```

---

## Step 4 — HTTP probe on all open ports

For every open port, check if it responds to HTTP/HTTPS:

```bash
# Build port list for httpx
python3 -I -c "
ports = '$OPEN_PORTS'.split(',')
for p in ports:
    p = p.strip()
    if p:
        print(f'http://$TARGET_IP:{p}')
        print(f'https://$TARGET_IP:{p}')
" | httpx \
    -status-code \
    -title \
    -tech-detect \
    -web-server \
    -follow-redirects \
    -silent \
    -json \
    -o "$OUTDIR/httpx_all_ports.jsonl" \
    2>/dev/null

echo "[+] HTTP-responding services:"
python3 -I -c "
import json
try:
    with open('$OUTDIR/httpx_all_ports.jsonl') as f:
        for line in f:
            d = json.loads(line.strip())
            url = d.get('url','')
            status = d.get('status_code','')
            title = d.get('title','')
            tech = d.get('tech', [])
            print(f'  {url} [{status}] {title} {tech}')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null
```

---

## Step 5 — Parse and categorize findings

```bash
python3 -I skills/port-scan/scripts/parse_results.py \
    "$OUTDIR/nmap_services.xml" \
    "$OUTDIR/httpx_all_ports.jsonl" \
    "$TARGET" \
    "$TARGET_IP" \
    "$OUTDIR/service_map.json"
```

---

## Step 6 — Triage and escalate

After parsing, assess each service:

| Port / Service | Priority | Likely Path |
|---|---|---|
| 22 (SSH) | Low — note only | Check banner for version |
| 80/443 | Standard | Route to `url-discovery` |
| 8080/8443 | Medium | Admin panel likely — route to `dark-recon` |
| 9200 (Elasticsearch) | Critical | Unauthenticated? Direct data exposure |
| 6379 (Redis) | Critical | Unauthenticated? RCE possible |
| 5432/3306/1433 | Critical | DB exposed? Check auth |
| 2375 (Docker daemon) | Critical | Unauthenticated? Container escape |
| Non-standard web port | Medium | Route to `dark-recon` |
| SMTP/25/587 | Low | Note open relay risk |
| Unknown service | Medium | Manual probe needed |

```bash
# Check for critical unauthenticated services
for port in 9200 6379 27017 2375 4001 8500; do
    if echo "$OPEN_PORTS" | grep -q "\b$port\b"; then
        echo "[!] HIGH-RISK port open: $port — check authentication immediately"
        case $port in
            9200) curl -sk "http://$TARGET_IP:9200/" | python3 -m json.tool ;;
            6379) echo -e "PING\r\n" | timeout 3 nc -q1 "$TARGET_IP" "$port" ;;
            27017) echo "[*] MongoDB — check with mongosh or nmap script" ;;
            2375) curl -sk "http://$TARGET_IP:2375/info" | python3 -m json.tool ;;
        esac
    fi
done
```

---

## Step 7 — Save findings

For each non-standard HTTP service found:
- `insert_assets` (kind: `app`) with the URL and service info
- `add_hint` for any critical unauthenticated service found

For critical unauthenticated services (Elasticsearch, Redis, Docker):
- Capture proof: the response from Step 6
- Mark as PROBABLE finding (severity: Critical)
- Add to evidence queue for validator review

---

## Constraints

- **Rate limit: 100 packets/sec** for naabu — do not increase without authorization
- **nmap -T3** — do not use -T4 or -T5 without explicit approval (DoS risk on fragile targets)
- **Do NOT scan the entire internet or /8-/16 ranges** — stay within scoped IPs
- **Scope guard**: verify TARGET_IP falls within authorized ranges before scanning
- **No SYN scan (-sS)** without root and explicit authorization — use connect scan (-sT) if unsure
- **Stop immediately** if target becomes unresponsive (rate-limited or taken down by scan)

## Tools Required

| Tool | Purpose |
|------|---------|
| `naabu` | Fast port discovery |
| `nmap` | Service/version fingerprint |
| `httpx` | HTTP probe on open ports |
| `dig` | DNS resolution |
| Python 3 | Result parsing |
