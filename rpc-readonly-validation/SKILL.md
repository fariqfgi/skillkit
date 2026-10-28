---
name: rpc-readonly-validation
description: Use when validating known RPC metadata read-only.
compatibility: Bash, Read and task report_finding.
---

# Read-only RPC metadata validation

## When to use
Use for a known JSON-RPC endpoint already recorded by `api-recon`, with an explicitly authorized bounded validation intent. Inventory-only or unauthenticated recon authority does not authorize this validation automatically.

## Prerequisites and boundaries
- Use `Read(file_path="<harvest>/api_static.txt", offset=1, limit=80)` plus the assigned scope/intent to resolve the exact approved scheme, hostname, port and endpoint path. No guessing other RPC paths, bundle-host pivots, aliases, cross-origin redirects or scope expansion.
- No credential harvesting or replay, authentication forgery, secrets in logs, customer enumeration, tracker filing, or automatic CORS-only probes/findings/retests (accepted risk). Use anonymous access by default; a supplied test identity needs separate documented authority and operator-managed secret injection.
- Prompt boundaries are defense-in-depth, not technical enforcement. An HTTP POST can be semantically read-only, but only the exact allowlist below is approved here.

## Method decision table
Allow only one JSON-RPC request object per HTTP request, `jsonrpc: "2.0"`, a local request ID and `params: []`:

| Allowed method | Observation |
|---|---|
| `rpc_modules` | Advertised namespace metadata, not proof methods are usable |
| `web3_clientVersion` | Reported client version, not proof of an exploitable CVE |
| `eth_chainId` | Chain identifier |
| `eth_blockNumber` | Current public block height |
| `net_version` | Network identifier |
| `net_listening` | Boolean listening status |

Deny every other method and non-empty parameters. Node mutation, profile writes, mining, transactions, signing, wallet/account operations, DoS, bulk logs, traces and tracer exploitation require separate explicit approval and a separately reviewed procedure outside this pack. This includes `debug_*`, `trace_*`, `admin_*`, `personal_*`, `miner_*`, `txpool_*`, `eth_sendTransaction`, `eth_sendRawTransaction`, `eth_sign`, `eth_call` and unknown methods. Do not test a forbidden method merely to see whether it exists. No batch requests or fake-method error probes.

## Procedure
1. First decide whether metadata is sufficient from existing evidence. If validation is not explicitly approved, stop at that inventory and make zero requests.
2. Select only necessary allowlisted methods; record the bounded plan before `Bash(command="<approved single RPC metadata request>", timeout_ms=20000)`. Use short foreground per-request commands with one shared count/deadline. Never use `curl -L`, disable TLS verification, print credentials, or enable verbose request dumps. Independently cap connect time at 3 seconds, total request time at 10 seconds and response input at 64 KiB; a shell timeout alone is insufficient.
3. Preserve a wire-level request transcript with credential/PII values replaced, the redacted response status/headers/body, timestamp, command/tool origin, exact endpoint and current intent. Examine JSON-RPC `error` versus `result`; HTTP 200 may contain an application error.
4. Treat metadata and namespace/version matches as observations. Named CVEs are not findings without applicable behavior and reproduced impact. Ordinary sandboxed tracer JavaScript arithmetic is intended functionality, not host RCE; no tracer is sent by this procedure.
5. A real security claim requires positive and negative controls within this same scope and allowlist, a repeat of the decisive observation, documented intended access, and honest demonstrated impact. If no adequate negative control exists, report an unverified lead, not a confirmed vulnerability.
6. Only for a confirmed independent vulnerability in task context, use `report_finding(vulnclass, severity, summary, name, intent_id, asset_ids, evidence)`: real current intent/asset IDs, severity `critical|high|medium|low`, verifiable command output/logs in redacted evidence. Public chain metadata is not an auth flaw by itself. Read back the exact finding with available task finding tools; if unavailable, state registration unverified. No tracker submission.

## Limits and stop conditions
At most 6 target requests and 90 seconds per assigned validation, including controls/repeats; serial, at most one request every 2 seconds. No explicit operator cost/token cap means inventory-only. Share a non-resetting aggregate of at most 40 requests and 600 seconds per target across this pack. Stop at the earliest task cost/token cap, six-hour scan deadline or earlier operator limit; also stop on any redirect, unexpected auth/session gate, 429, 5xx, unexpected load or sensitive data. No automatic retries or background probing.

## Verification
Account for every request and allowlist decision. Return observations, reproduced impact if any, exclusions and missing controls. Do not upgrade a version fingerprint, module list, co-tenancy or a status code to speculative severity, exploitation or coverage.
