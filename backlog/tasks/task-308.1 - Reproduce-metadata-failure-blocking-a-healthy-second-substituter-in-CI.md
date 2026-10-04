---
id: TASK-308.1
title: Reproduce metadata failure blocking a healthy second substituter in CI
status: In Progress
assignee: []
created_date: '2026-10-04 21:23'
updated_date: '2026-10-04 21:33'
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
- [ ] #1 Old module/client configuration fails on metadata 502 or 503 with a healthy second cache, and logs prove that cache did not serve the target.
- [ ] #2 Corrected configuration realizes matching signed content from the second cache with all builders disabled; bad signatures or corrupt payloads never become valid store paths.
- [ ] #3 Regression is registered in existing CI gates; before/after evidence and exact commands recorded.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Test-first draft registers substituter-errors in the Podman harness, just e2e selection, and an early CI step. Uses shipped daemon-libp2p in upstream-only profile, evaluated module fallback/signature policy, fresh real nix-daemon and untrusted caller per arm. Covers 404 fidelity, metadata 503, transport-reset 502, module-disabled/explicit opt-out controls, signed realization, foreign-key/hash-mismatch rejection, exact target origin requests and explicit invalid-path diagnostics. Live HTTP reproduction: direct upstream404 in0.27s, local502 in15.30s with TLS timeout and excluded active egress interface. No live Nix realization claimed. Parallel QA/architecture static reviews approved; pinned Python/Ruff/Nix syntax and image derivation evaluation passed. E2E unrun and baseline expected red. Using previously authorized draft-CI commit exception because CI-only execution requires a pushed commit before the gate can run; no merge/deploy permitted by that exception. A red initial regression step skips subsequent normal/full gates.
<!-- SECTION:NOTES:END -->
