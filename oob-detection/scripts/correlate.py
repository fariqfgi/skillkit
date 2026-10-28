#!/usr/bin/env python3 -I
"""
Correlate interactsh OOB interaction logs with probe records.
Matches unique tokens in interaction hostnames back to probe parameters.

Usage:
    python3 correlate.py <interactions.jsonl> <probe_log.json> <confirmed_oob.json>
"""
import json
import sys
from pathlib import Path


def load_interactions(path: Path) -> list[dict]:
    interactions = []
    if not path.exists():
        return interactions
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            interactions.append(json.loads(line))
        except Exception:
            pass
    return interactions


def load_probe_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def extract_token(hostname: str) -> str | None:
    """Extract the 16-char hex token from the OOB subdomain."""
    parts = hostname.lower().split(".")
    if parts:
        candidate = parts[0]
        if len(candidate) == 16 and all(c in "0123456789abcdef" for c in candidate):
            return candidate
    return None


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <interactions.jsonl> <probe_log.json> <confirmed_oob.json>", file=sys.stderr)
        sys.exit(1)

    interactions_file = Path(sys.argv[1])
    probe_log_file = Path(sys.argv[2])
    out_file = Path(sys.argv[3])

    interactions = load_interactions(interactions_file)
    probes = load_probe_log(probe_log_file)

    if not interactions:
        print("[ ] No OOB interactions found.", file=sys.stderr)
        out_file.write_text(json.dumps({"confirmed": [], "raw_interactions": []}, indent=2))
        return

    # Build token → probe mapping
    token_to_probe: dict[str, dict] = {}
    for probe in probes:
        token = probe.get("token", "")
        if token:
            token_to_probe[token] = probe

    # Correlate interactions → probes
    confirmed = []
    for interaction in interactions:
        # interactsh-client JSON fields
        full_id = interaction.get("full-id", interaction.get("unique-id", ""))
        protocol = interaction.get("protocol", "unknown")
        remote_addr = interaction.get("remote-address", "")
        raw_request = interaction.get("raw-request", "")
        timestamp = interaction.get("timestamp", "")

        token = extract_token(full_id)
        matched_probe = token_to_probe.get(token) if token else None

        entry = {
            "interaction_id": full_id,
            "protocol": protocol,
            "remote_address": remote_addr,
            "timestamp": timestamp,
            "raw_request_preview": raw_request[:500] if raw_request else "",
            "token": token,
            "matched_probe": matched_probe,
            "confirmed": matched_probe is not None,
        }
        confirmed.append(entry)

        if matched_probe:
            param = matched_probe.get("param", "unknown")
            probe_type = matched_probe.get("type", "unknown")
            target_url = matched_probe.get("url", "unknown")
            print(f"[!] OOB CONFIRMED: {probe_type} via param '{param}' on {target_url}", file=sys.stderr)
            print(f"    Protocol: {protocol}, Remote: {remote_addr}", file=sys.stderr)
        else:
            print(f"[?] Unmatched OOB interaction: {full_id} ({protocol})", file=sys.stderr)

    correlated = [e for e in confirmed if e["confirmed"]]
    unmatched = [e for e in confirmed if not e["confirmed"]]

    output = {
        "summary": {
            "total_interactions": len(interactions),
            "confirmed_hits": len(correlated),
            "unmatched": len(unmatched),
        },
        "confirmed": correlated,
        "unmatched": unmatched,
        "raw_interactions": interactions,
    }

    out_file.write_text(json.dumps(output, indent=2))
    print(f"[+] Correlation complete: {len(correlated)} confirmed, {len(unmatched)} unmatched", file=sys.stderr)


if __name__ == "__main__":
    main()
