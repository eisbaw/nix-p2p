---
id: TASK-308.1
title: Reproduce metadata failure blocking a healthy second substituter in CI
status: Done
assignee: []
created_date: '2026-10-04 21:23'
updated_date: '2026-10-05 07:47'
labels: []
dependencies: []
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add a deterministic real-Nix Podman regression before changing product behavior. Exercise the shipped daemon and signed local fixture caches, with cold client stores and no Internet dependency. Include genuine upstream 404, HTTP 503, and an unreachable upstream causing daemon 502. Record the Nix version and resolved fallback setting. Baseline must expose the existing failure rather than assuming HTTP status alone proves build behavior.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Old module/client configuration fails on metadata 502 or 503 with a healthy second cache, and logs prove that cache did not serve the target.
- [x] #2 Corrected configuration realizes matching signed content from the second cache with all builders disabled; bad signatures or corrupt payloads never become valid store paths.
- [x] #3 Regression is registered in existing CI gates; before/after evidence and exact commands recorded.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Baseline proven in CI run 37238155359 on commit 379c087a34b0e5817a1cc97f215cd085c35276f8: `nix develop -c just e2e '--only substituter-errors'` finished with 192/206 checks in 120.3 seconds (expected failure). With fallback=false, exact Nix 2.31.2 succeeds after preferred-cache 404 but exits 1 on 502/503 before the second cache serves target metadata or payload. Exact Nix 2.34.8 succeeds for all three statuses. Successful realizations match the signed NarHash with require-sigs=true, max-jobs=0, and no remote builders. Both client and daemon versions are asserted. The fourteen failed checks concern the older enabled-policy error cases and tamper arms that cannot reach the second cache before the fix. Build/lint/unit/commit-message and audit jobs passed; later default/full E2E steps were skipped.

Earlier attempts are not reproduction evidence: run 37236655606 was canceled to add the affected Nix version; run 37237095595 failed before realization in an untrusted version probe. The corrected probe shares the realization environment and reports stderr.

The baseline follows a live HTTP diagnostic: direct upstream 404 in 0.27 seconds versus localhost 502 in 15.30 seconds, with a daemon TLS timeout and excluded active egress interface. This was not evidence of 404-to-502 translation. Product fallback fix is now prepared for CI; passing evidence remains pending. Draft CI commits use the previously authorized gate-placement exception; no merge or deployment is implied.

Green implementation evidence: CI run 37240672888 on exact commit a11d6ee7819a34cc886312c972191d42b00755db. The command nix develop -c just e2e with --only substituter-errors passed 204/204 checks in 118.7s; default just e2e passed all 19 scenarios, and just e2e-full passed all 49. Both exact Nix 2.31.2 and 2.34.8 realize signed matching content after 404/502/503 under the enabled module policy. Older disabled/explicit-opt-out controls still fail on 502/503 before second-cache access. Foreign signatures and signed-hash mismatches reach the second cache and remain rejected. The green count is two lower than baseline because successful enabled-policy realizations no longer execute the invalid-path diagnostic checks. VM job was skipped; these are Podman results.
<!-- SECTION:NOTES:END -->
