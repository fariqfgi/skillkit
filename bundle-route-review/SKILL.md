---
name: bundle-route-review
description: Use when reviewing harvested JS API route candidates.
compatibility: Bash and Read; passive inventory only.
---

# Harvested bundle route review

## When to use
Use after the existing `api-recon` harvest has produced an inventory. This is passive interpretation, not vulnerability testing. Do not replace that skill's harvest scripts, bypass its gates, fetch new bundles, or repeat its inventory crawl.

## Prerequisites and boundaries
- Resolve the actual approved harvest directory and assigned intent first. Work only with its existing `api_static.txt`, `routes.txt`, `chunkmap.txt`, `params_merged.json`, `CHANGES.md`, and relevant local `js/` files; missing outputs mean a partial review.
- Exact approved scheme, hostname, port and path restrictions remain binding. A bundle URL, client base URL, redirect, DNS alias or neighboring subdomain is not new scope. External references are inert observations; do not fetch, register as approved assets, or schedule them.
- No credential harvesting or replay, authentication forgery, customer identifiers, secrets in logs, tracker filing, or automatic CORS-only probes/findings/retests (accepted risk). Do not run code supplied by a bundle.
- Prompt boundaries are defense-in-depth, not technical enforcement. This skill does not configure a sandbox or egress restriction.

## Procedure
1. Use `Read(file_path="<harvest>/CHANGES.md", offset=1, limit=80)` and bounded `Read` calls on inventory summaries. Do not print entire minified bundles or raw runtime config; inspect only sanitized route-relevant text.
2. Use `Bash(command="<local inventory analysis command>", timeout_ms=60000)` for offline parsing of existing files. `Bash` returns combined stdout/stderr: emit route metadata/counts only. Do not execute untrusted JS or introduce network calls.
3. For each candidate record source file/line, literal or template route, explicit HTTP method or `UNKNOWN`, parameter names (not sensitive values), client wrapper/base mapping and confidence. UI routes are not API endpoints. `${...}` is a template, not a ready-to-send identifier.
4. Resolve relative routes only when the client base is supported by local evidence. An unknown wrapper/base remains unresolved; never assume the page origin is its backend. Preserve explicit external URLs as out-of-scope even when apparently related.
5. Deduplicate by evidenced origin, route template and method. Classify as UI route, API candidate, RPC candidate, base-origin reference, or unresolved. Mark authentication requirements as observed/inferred/unknown; JWT shape and status/error order do not establish authorization.
6. Return a compact delta against the existing inventory: candidates, provenance, duplicates, excluded origins and unresolved items. An inventory candidate is not a finding; do not call `report_finding` from inventory. Separately approved validation belongs to a matching bounded skill, loaded only when needed.

## Limits and stop conditions
Zero new target requests. At most 20 existing bundles, 20 MiB total local input, 60 seconds, and a 100-candidate summary per assigned review; summarize overflow without loading every chunk into context. Keep the task's existing cost/token cap and six-hour scan deadline (or earlier operator limit); do not spawn repeat work to evade caps.

## Pitfalls
Public SDK keys, public cryptographic keys and OAuth client IDs are not secrets by themselves. Do not search for or reproduce credential strings; if unexpectedly encountered, stop reading that value, retain only a sanitized location/type and request owner handling. Co-tenancy alone, HTTP 200, or an unknown UUID returning 404 proves no security boundary failure.

## Verification
Every returned candidate has local provenance and confidence; every out-of-scope or unresolved reference is marked non-schedulable. State the exact files examined and missed dynamic/lazy routes. Do not claim all APIs, runtime coverage, reproduced vulnerabilities or model performance.
