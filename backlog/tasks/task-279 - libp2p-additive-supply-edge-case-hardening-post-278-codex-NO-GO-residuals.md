---
id: TASK-279
title: libp2p additive-supply edge-case hardening (post-278 codex NO-GO residuals)
status: To Do
assignee: []
created_date: '2026-08-20 03:49'
labels:
  - hardening
  - follow-up
dependencies:
  - TASK-278
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred edge-case findings from the codex DEEP re-review of TASK-278 Part A (Mark-emulator arbitrated: none reintroduces the silent-drop, none puts a bad byte/store path on the wire, worst peer cost is a TTL-bounded retry -> inside TCB, filed as hardening while the normal additive path ships).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 codex #1 (seed/hook shared-key GC tombstone; STATE MACHINE): a node with a static seed for NarHash H that ALSO self-realizes+announces H via announce-after-fetch, then GCs that store path, MUST remain discoverable for H. Fix: (a) the hook refuses to register/announce/withdraw a NarHash owned by the durable (memory-resident, never-GC'd) seed leg, OR (b) reconcile() drops the withdrawn key from 'announced' in lockstep with 'held' so a re-fetch can re-announce (no AlreadyHandled tombstone). Biting unit ledger test: seed-owned key + store-GC + re-fetch => still announced, RED under current code
- [ ] #2 codex #2 (public mixed-allowlist non-atomic publish; TRANSACTION): on public-share, authorize EVERY leg (seeds AND provisions) against the TASK-103 allowlist BEFORE announcing ANY record; on any refusal no record is published (or every published record is withdrawn before Err). Biting test: after the induced P-refusal, a kad get_providers for the allowlisted seed S returns nothing; mutation restoring announce-before-full-authz => S lingers to TTL
- [ ] #3 codex #5 (profile-native parse ordering; NORTH-STAR path): --profile lan-share --libp2p-seed-nar S --libp2p-announce-after-fetch with NO explicit --libp2p-provider MUST succeed on both binaries (run the lan-share provider back-fill BEFORE the announce-after-fetch companion check). Biting test: parse this exact argv => provider with announce_after_fetch on; mutation restoring ordering => Err
- [ ] #4 codex #7 (S10 e2e coverage): add a daemon-libp2p variant (thin binary additive path e2e-covered, not unit-only); drive the provider to SELF-FETCH the static seed through its own daemon (seed proven SERVED from the union under real fetch, not merely announced); assert the additive REPORT LINE in the provider log; correct the S10 docstring + SEED-PRESENCE comment to state the mutation reddens the SERVE oracle (0 upstream), not the announce-presence oracle
<!-- AC:END -->
