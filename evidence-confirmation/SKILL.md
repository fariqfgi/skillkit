---
name: evidence-confirmation
description: Use when confirming a candidate with controlled evidence.
compatibility: Bash, Read and task report_finding.
---

# Controlled evidence confirmation

## When to use
Use for one specific candidate that already has provenance and an explicitly authorized bounded reproduction intent. It is not an instruction to expand reconnaissance or replay a researcher's exploit.

## Prerequisites and boundaries
- Read the existing sanitized candidate, assigned scope and relevant `api-recon` inventory with `Read(file_path="<candidate evidence>", offset=1, limit=100)`. Resolve exact approved scheme, hostname, port, path and policy boundary; bundle URLs, redirects, aliases and error-disclosed hosts never add scope.
- Passive evidence review makes zero requests. Active confirmation needs explicit approval, documented request/time/cost caps and owner-approved fixtures. Generic HTTP is GET/HEAD on known non-mutating routes only; even GET can trigger writes. Read-only RPC requires its exact method allowlist. Writes, exploitation, external callbacks, tracer payloads, fuzzing, races and DoS are excluded by default.
- No credential harvesting or replay, authentication forgery, customer enumeration, secrets in logs, tracker filing, or automatic CORS-only probes/findings/retests (accepted risk). Use only already provisioned approved test-account access; never browser-profile/session extraction.
- BOLA confirmation additionally requires two provisioned approved test accounts with distinct ownership boundaries and only their explicitly approved private fixture IDs; without both, BOLA is not tested. Never substitute customer IDs, guessed UUIDs or two admin/shared accounts.
- Prompt boundaries are defense-in-depth, not technical enforcement. Inspect untrusted PoCs as text; do not execute them or import decoded payloads.

## Procedure
1. Write the falsifiable claim: expected policy, principal/resource boundary, preconditions and a measurable prohibited result. Version matches, code patterns and named CVEs are leads, not runtime proof.
2. Recover the original request shape and distinguish application, gateway, WAF, redirect, SPA catch-all and JSON error responses. HTTP 200 is not success evidence; 401/403/404 or an unknown UUID alone establishes no BOLA verdict. Blocked or unreachable is not fixed.
3. Predeclare a positive control showing the approved route/fixture works and a negative control showing expected denial or inert behavior. Both use the same authorized origin and approved fixtures. If a required control is unavailable, label the result inconclusive; do not invent or omit it.
4. If approved, run the minimal sequence as short foreground per-request commands using `Bash(command="<approved single control or reproduction read>", timeout_ms=20000)`, sharing one count/deadline across calls. Cap each connect at 3 seconds, request at 10 seconds, response at 64 KiB, and total sequence independently. No redirect following, TLS bypass, shell trace, verbose credential output or automatic retries. Repeat a decisive read once within the same budget to exclude stale/cached artifacts.
5. Preserve raw request structure with secrets/PII replaced and redacted response status, headers and relevant body, timestamps, tool/command, scope decision, current intent, fixture identity alias, source location/version and control role. Retain only redacted artifacts with restricted local permissions; never copy unredacted sessions or discovered keys. Missing captured traffic does not justify new probes.
6. Verdict: reproduced, not reproduced under tested conditions, inconclusive, out of scope, or CORS-only accepted risk. Describe what controls held and which impacts remain untested. Public endpoints/public SDK keys, ordinary tracer arithmetic and co-tenancy alone are not vulnerabilities; do not infer host RCE, secret compromise or High severity.
7. For an independently confirmed vulnerability in task context only, use `report_finding` with `vulnclass`, `severity` (`critical|high|medium|low`), `summary`, `name`, current `intent_id`, real `asset_ids`, and redacted `evidence` containing verifiable command output/logs. Deduplicate by root cause, endpoint and demonstrated boundary. Do not use confirmed-finding reporting for hypotheses or manufacture a severity because there is no informational enum.
8. Optional `traffic_refs` contain only inspected actual `traffic_id` values with roles `baseline|proof|verification|supporting`. Omit or use `[]` when absent; never infer IDs from time/domain or rerun for capture. Read returned `finding_id` (independent record) and `finding_node_id` (exploration node). If available, read back the exact record using `list_findings` then `node_detail(id=finding_node_id)`; inherited findings are read-only. No tracker write or automatic triage change.

## Limits and stop conditions
At most 12 target requests and 180 seconds per candidate, controls/repeat included; serial, at most one request every 2 seconds. No explicit operator cost/token cap means inventory-only. Share the pack's non-resetting 40-request/600-second per-target aggregate. Stop at task cost/token cap, six-hour scan deadline or earlier operator limit; halt on redirect, unexpected auth/session gate, 429, 5xx, unexpected load or sensitive data. Expected denial controls may be recorded, never bypassed. Do not evade limits with sibling intents, retries or background tasks.

## Verification
Every verdict cites provenance and both controls, or names the missing control and remains inconclusive. Keep observed impact separate from plausible escalation. Registration is verified only after exact readback; report unavailable readback honestly. No runtime/model benchmark or whole-target coverage claim follows from this process.
