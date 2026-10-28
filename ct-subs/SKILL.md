---
name: ct-subs
description: Enumerate subdomains for one or more domains from Certificate Transparency logs (certspotter API primary, crt.sh JSON fallback with backoff). Use during reconnaissance when asked for subdomains, asset discovery, or certificate-surface mapping.
---

# CT subdomain enumeration

Run the bundled script — it handles provider flakiness for you (crt.sh regularly returns 429/502/502-gateway; certspotter is the stable primary):

```bash
python3 skills/ct-subs/scripts/ct_subs.py okx.com okex.com okg.com -o ct_subs.json
```

- Output: JSON mapping each domain to its sorted unique subdomain names (wildcards stripped, lowercased).
- Both providers are queried and merged when both succeed; on certspotter failure the script falls back to crt.sh with 3 exponential-backoff attempts.
- Anonymous certspotter caps at ~100 issuances per call — for very large zones, chunk by known subdomain hints (`-q` style follow-ups) or merge multiple runs over time.
- Always diff the result against any already-known asset list before probing; CT only proves a certificate was issued, not that the host is alive.
- Stay within the target's authorized scope: CT data is public and passive, but HTTP probes against enumerated hosts must respect the program rules.
