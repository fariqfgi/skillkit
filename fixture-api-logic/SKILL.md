---
name: fixture-api-logic
description: Use when checking fixture API authorization or read logic.
compatibility: Bash, Read and task report_finding.
---

# Fixture-only API authorization and read logic

## When to use
Use for explicit bounded BOLA/read-logic validation of endpoints already inventoried by `api-recon`. On ordinary unauthenticated radar scans without approved fixtures/accounts, stop at inventory; do not enumerate users or invent object IDs.

## Prerequisites and boundaries
- Use `Read(file_path="<harvest>/params_merged.json", offset=1, limit=80)` and the assigned intent to establish exact approved scheme, hostname, port, paths, documented non-mutating semantics and intended access policy. Unknown client bases, bundle URLs, aliases, redirects and related subdomains add no scope.
- BOLA requires two provisioned approved test accounts A/B with genuinely distinct ownership boundaries and an explicit list of their own private fixture IDs/markers. Both accounts and all tested IDs, including any nonexistent fixture ID, must be owner approved before testing. Never customer enumeration, UUID guessing, directory harvesting, numeric ranges or arbitrary borrowed IDs.
- No credential harvesting or replay, authentication forgery, secrets in logs, tracker filing, or automatic CORS-only probes/findings/retests (accepted risk). Already provisioned A/B access uses operator-managed secret injection; do not obtain it from bundles, browser profiles or other users.
- GET/HEAD reads only on documented non-mutating routes. Writes are excluded by default: no PUT/PATCH/DELETE, mutating POST, GET-delete/logout/action links, object creation, checkout, redemption, payment, transactions, bulk/race tests or rate-limit bypass. POST-based read queries need a separately reviewed approval; blockchain RPC belongs to its dedicated allowlist.
- Prompt boundaries are defense-in-depth, not technical enforcement. If prerequisites or explicit validation authority are missing, make zero validation requests and state the limitation.

## Procedure
1. Build a finite matrix from inventoried paths and approved fixture IDs; no opportunistic additions. Expected results are private owner read succeeds, wrong owner/unauthenticated read denies, and public content remains public.
2. For BOLA, first verify A reads A's fixture and B reads B's fixture (positive controls) and a known owner-approved protected control denies an unauthorized principal (negative control). Validate response schema and the distinctive non-sensitive fixture marker, not merely status.
3. Swap only A/B approved fixture IDs in the same read route, without changing roles or credentials; repeat one decisive read inside budget. A→B or B→A is a finding only when documented-private fixture content crosses the provisioned ownership boundary and controls show the test harness is valid. Two admin accounts or shared/public fixtures cannot prove that boundary.
4. For read-only business logic, compare documented projections/filters on these same fixture-owned records against the expected policy. Include an allowed and denied/inert control. Do not infer discount, financial, workflow or write impact from a read response; such chains are outside this procedure.
5. Execute the finite matrix as short foreground per-request commands using `Bash(command="<approved single fixture read>", timeout_ms=20000)`, sharing one count/deadline across calls. Independently bound connect at 3 seconds, request at 10 seconds, response at 64 KiB and sequence time. No redirect following, TLS bypass, verbose credential dumps, automatic retries or background work.
6. Retain raw request shape with credentials/PII replaced, redacted response status/headers/body, timestamp, tool/command provenance, fixture alias, ownership policy, exact scope and current intent. Stop on unexpected real customer data and retain no raw PII. HTTP 200 on a public endpoint or application error is not BOLA; nonexistent UUID/404 and auth-before-lookup ordering alone prove nothing.
7. For a confirmed violation in task context, use `report_finding(vulnclass, severity, summary, name, intent_id, asset_ids, evidence)` with real IDs, severity `critical|high|medium|low`, and redacted verifiable command output/logs including both controls. Keep impact limited to what crossed the tested boundary. Read back the exact finding using available task finding tools before claiming registration verified; no tracker filing. Otherwise return bounded negative/inconclusive observations, not a confirmed finding.

## Limits and stop conditions
At most 16 target requests, 2 provisioned accounts, 4 approved fixture IDs and 180 seconds per assigned matrix, including controls and repeat; serial, at most one request every 2 seconds. No explicit operator cost/token cap means inventory-only. Share the pack's non-resetting 40-request/600-second per-target aggregate. Stop at task cost/token cap, six-hour scan deadline or earlier operator limit, redirect, unexpected auth/session gate, 429, 5xx, unexpected load or sensitive data. Expected denial controls may be recorded, never bypassed. Never reset counters or spawn a wider enumeration to manufacture a finding.

## Verification
Account for every tested matrix cell and ID; identify skipped cells and why. A reproduced boundary violation needs private fixture markers, valid positive/negative controls and a decisive repeat. No accounts/fixtures means BOLA not tested, not safe; no write coverage, customer coverage or model benchmark is claimed.
