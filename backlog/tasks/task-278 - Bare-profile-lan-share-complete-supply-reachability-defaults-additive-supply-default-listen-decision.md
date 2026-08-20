---
id: TASK-278
title: >-
  Bare --profile lan-share complete supply + reachability defaults (additive
  supply; default-listen decision)
status: To Do
assignee: []
created_date: '2026-08-20 00:25'
updated_date: '2026-08-20 01:22'
labels:
  - usability
  - cornerstone
  - follow-up
dependencies:
  - TASK-273
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Root-causes codex finding #1 and completes the zero-config supply story that TASK-273 (narrowed to discovery-only) deliberately deferred. Absorbs TASK-276 (cross-host serving / lan-isolation).

Why: forcing announce-after-fetch selected an EXCLUSIVE store-supply mode that silently bypassed --libp2p-seed-nar and falsely reported seeded NARs. The fix is additive supply, not a default flip on a broken seam.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 install_provider is ADDITIVE: unions --libp2p-seed-nar + --libp2p-provide-store + announce-after-fetch dynamic supply; the startup report reflects the ACTUAL served set (no false count)
- [ ] #2 INTERIM until additive lands: seed-nar together with announce-after-fetch FAILS CLOSED (never silently drops the seed)
- [ ] #3 Decide + implement the default listen for a bare lan-share (loopback vs allowlist-gated routable) — the cross-host SERVING question (absorbs TASK-276)
- [ ] #4 Re-enable the announce-after-fetch + listen defaults under lan-share ONLY once additive supply is proven safe; re-gate (DEEP)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
codex re-review confirmed finding #1 persists on the EXPLICIT announce-after-fetch path (main.rs:1059 store/grow mode reads only provide_store, bypasses seed_nar; false report main.rs:1650; composite daemon/src/main.rs:1891/2110/2350). Doing the INTERIM fail-closed now (seed_nar + announce-after-fetch together -> error, both binaries) as a 278 down-payment; full additive supply remains.
<!-- SECTION:NOTES:END -->
