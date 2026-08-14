---
id: TASK-214
title: >-
  kad discovery: deterministic smallest-PeerId fan-out selection is a
  targeted-key censorship vector
status: To Do
assignee: []
created_date: '2026-08-14 21:59'
labels:
  - discovery
  - adversarial
  - availability
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by the TASK-154 mped-architect review (2026-08-14), F1. PRE-EXISTING (the old cap_fan_out had it too); TASK-154's B2 fix makes it OBSERVABLE. At prod defaults max_peers=16 vs STORE_MAX_PROVIDERS_PER_KEY=20, the named provider union routinely exceeds 16. PeerIds are grindable, so an attacker can mint identities that sort into the 16 smallest slots and permanently evict a legit provider for a CHOSEN key -> perpetual Unavailable(truncated). INTEGRITY HOLDS (no bad store path), but discovery-AVAILABILITY for that key is denied, and deterministic retry with the same budget re-chases the same dead 16, so it does not self-heal. Fix candidates: randomized/rotating selection among the named set, or a per-query salt, so a griefer cannot deterministically own the retained slots; at minimum document the vector in the fan-out threat-model comment. Relates to TASK-154 (fan-out bound) and TASK-205 (adversarial-swarm field proof).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The retained fan-out subset is not deterministically grindable: an attacker minting PeerIds cannot guarantee eviction of a specific legit provider for a chosen key across retries (randomized/rotating/salted selection)
- [ ] #2 A key whose legit provider is out-competed on one query can still be resolved on retry (self-heals; retry does not re-chase the identical dead subset)
- [ ] #3 If the residual risk is accepted rather than fully closed, it is documented in the fan-out threat-model comment with the honest bound
<!-- AC:END -->
