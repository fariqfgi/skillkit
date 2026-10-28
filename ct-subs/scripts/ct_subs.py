#!/usr/bin/env python3
"""ct_subs.py <domain> [<domain>...] [-o OUT.json]

Certificate-transparency subdomain enumeration with graceful fallback:
1. certspotter API (primary — stable, returns dns_names incl. wildcards)
2. crt.sh JSON API (fallback — frequently 502/429; 3 attempts, exponential backoff)

stdlib only. Writes {domain: [names...]} to OUT.json (default: ct_subs_<ts>.json).
"""
import json, sys, time, urllib.request, urllib.error

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Artifex-ct-subs"}
WILDCARD_PREFIX = "*."


def _get(url, timeout=90):
    req = urllib.request.Request(url, headers=UA)
    return urllib.request.urlopen(req, timeout=timeout)


def via_certspotter(domain):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    names = set()
    # unauthenticated API paginates via "issuances" of later batches; single call
    # already covers everything with include_subdomains, 100-issuance cap on anon tier
    data = json.load(_get(url))
    for iss in data:
        for n in iss.get("dns_names", []):
            names.add(n.lstrip(WILDCARD_PREFIX).lower())
    return names


def via_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names = set()
    last_err = None
    for attempt in range(3):
        try:
            data = json.load(_get(url))
            for e in data:
                for n in e.get("name_value", "").split("\n"):
                    n = n.strip().lstrip(WILDCARD_PREFIX).lower()
                    if n:
                        names.add(n)
            return names
        except Exception as e:
            last_err = e
            time.sleep(5 * (attempt + 1))  # crt.sh flaps 429/502; back off and retry
    print(f"  [!] crt.sh failed after 3 attempts ({last_err}); using partial results", file=sys.stderr)
    return names


def main():
    argv = sys.argv[1:]
    out = "ct_subs_%d.json" % int(time.time())
    if "-o" in argv:
        i = argv.index("-o")
        out = argv[i + 1]
        del argv[i:i + 2]
    domains = [a for a in argv if not a.startswith("-")]
    if not domains:
        print(__doc__); sys.exit(1)

    result = {}
    for domain in domains:
        print(f"[*] {domain}: certspotter...", file=sys.stderr)
        names = set()
        try:
            names = via_certspotter(domain)
        except Exception as e:
            print(f"  [!] certspotter failed ({e}); falling back to crt.sh", file=sys.stderr)
        if not names:
            names = via_crtsh(domain)
        else:
            # merge a crt.sh attempt for anything certspotter's anon cap missed
            try:
                names |= via_crtsh(domain)
            except Exception:
                pass
        result[domain] = sorted(names)
        print(f"  -> {len(names)} unique names", file=sys.stderr)

    with open(out, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"[+] written {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
