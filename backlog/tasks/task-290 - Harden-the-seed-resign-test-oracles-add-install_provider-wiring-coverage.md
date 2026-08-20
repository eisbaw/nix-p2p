---
id: TASK-290
title: Harden the seed-resign test oracles + add install_provider wiring coverage
status: To Do
assignee: []
created_date: '2026-08-20 23:58'
labels:
  - hardening
  - test
  - follow-up
dependencies:
  - TASK-285
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Residual test-rigor items from the TASK-285 DEEP gate (codex + mped), filed rather than ground round-by-round. The seed-resign feature is correct + gated; these tighten its oracles against now-stable code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 past-TTL negative control (seed_resign_past_ttl.rs) attributes to the reached-but-expired seam: establish a same-consumer PRE-expiry Lookup::Found, THEN require a POST-expiry Miss - not any first Miss (which also means empty-index/never-reached).
- [ ] #2 the concurrent-persist RED bite (announcer.rs ~783) replaces its 400ms sleep margin with an explicit lock-contention signal (B has blocked on persist_lock) so the mutation-RED is not timing-dependent.
- [ ] #3 add container-scenario (e2e_harness.py) coverage of the install_provider -> spawn_seed_resign WIRING (currently only spawn_seed_resign is unit-tested directly); drive a --libp2p-record-ttl-secs short-TTL node and assert a fresh consumer discovers past the TTL.
<!-- AC:END -->
