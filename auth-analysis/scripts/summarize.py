#!/usr/bin/env python3 -I
"""
Summarize auth-analysis results from an output directory.
Scans for finding signals in the captured files and produces a structured report.

Usage:
    python3 summarize.py <outdir> <auth_findings.json>
"""
import json
import re
import sys
from pathlib import Path


BYPASS_SUCCESS_RE = re.compile(r"\bHTTP 200\b|\b\"200\"\b")
JWT_WEAK_ALG_RE = re.compile(r'"alg"\s*:\s*"(none|HS256|RS256)"', re.IGNORECASE)
ACTUATOR_OPEN_RE = re.compile(r'actuator.*\b200\b', re.IGNORECASE)
XMLRPC_ENABLED_RE = re.compile(r"<methodResponse|faultCode", re.IGNORECASE)
PRIV_ESC_RE = re.compile(r"PRIVILEGE ESCALATION", re.IGNORECASE)
IDOR_RE = re.compile(r"IDOR", re.IGNORECASE)


def scan_file(path: Path, pattern: re.Pattern) -> list[str]:
    try:
        text = path.read_text(errors="replace")
        return [m.group(0) for m in pattern.finditer(text)]
    except Exception:
        return []


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <outdir> <auth_findings.json>", file=sys.stderr)
        sys.exit(1)

    outdir = Path(sys.argv[1])
    out_file = Path(sys.argv[2])

    findings = []

    # JWT analysis
    jwt_file = outdir / "jwt_decoded.txt"
    if jwt_file.exists():
        content = jwt_file.read_text(errors="replace")
        alg_match = JWT_WEAK_ALG_RE.search(content)
        if alg_match:
            alg = alg_match.group(1)
            findings.append({
                "type": "jwt_weak_algorithm",
                "severity": "High" if alg in ("HS256",) else "Critical",
                "detail": f"JWT uses algorithm: {alg}",
                "status": "PROBABLE",
            })

    # alg:none test result
    none_file = outdir / "jwt_none_payloads.txt"
    if none_file.exists() and BYPASS_SUCCESS_RE.search(none_file.read_text(errors="replace")):
        findings.append({
            "type": "jwt_alg_none_accepted",
            "severity": "Critical",
            "detail": "JWT with alg:none returned HTTP 200 on protected endpoint",
            "status": "PROBABLE",
        })

    # XMLRPC
    xmlrpc_file = outdir / "xmlrpc_probe.txt"
    if xmlrpc_file.exists() and XMLRPC_ENABLED_RE.search(xmlrpc_file.read_text(errors="replace")):
        findings.append({
            "type": "xmlrpc_enabled",
            "severity": "Medium",
            "detail": "XMLRPC endpoint enabled — potential credential brute-force or legacy bypass",
            "status": "PROBABLE",
        })

    # Auth bypass (check all response files for bypass success)
    for candidate in outdir.glob("*.txt"):
        content = candidate.read_text(errors="replace")
        if PRIV_ESC_RE.search(content):
            findings.append({
                "type": "privilege_escalation",
                "severity": "Critical",
                "detail": f"Privileged endpoint returned 200 with regular-user token ({candidate.name})",
                "status": "PROBABLE",
            })
        if IDOR_RE.search(content):
            findings.append({
                "type": "idor",
                "severity": "High",
                "detail": f"IDOR candidate detected ({candidate.name})",
                "status": "PROBABLE",
            })

    # Actuator exposure (from stderr captures in nmap/curl runs)
    for candidate in outdir.glob("*.txt"):
        if ACTUATOR_OPEN_RE.search(candidate.read_text(errors="replace")):
            findings.append({
                "type": "actuator_exposed",
                "severity": "Medium",
                "detail": "Spring Boot actuator endpoint returned 200 without auth",
                "status": "PROBABLE",
            })
            break

    output = {
        "findings_count": len(findings),
        "findings": findings,
        "outdir": str(outdir),
    }

    out_file.write_text(json.dumps(output, indent=2))

    print(f"[+] Auth findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['type']}: {f['detail'][:80]}")


if __name__ == "__main__":
    main()
