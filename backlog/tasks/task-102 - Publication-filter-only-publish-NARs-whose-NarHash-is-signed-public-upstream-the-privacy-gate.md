---
id: TASK-102
title: >-
  Publication filter: only publish NARs whose NarHash is signed-public upstream
  (the privacy gate)
status: To Do
assignee: []
created_date: '2026-08-10 10:03'
updated_date: '2026-08-10 10:03'
labels:
  - wave-2b
dependencies:
  - TASK-95
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DECISION 2026-08-10, and it is the gate that unblocks global publication: a node publishes ONLY content that is already public at cache.nixos.org. That resolves the no-enumeration tension directly - anyone with the same nixpkgs can already derive these hashes, so publishing them discloses no secret. Locally built and private paths are NEVER published and stay reachable only by direct hold-query.

This is a PREREQUISITE for TASK-73 / TASK-102 (global DHT publication) and must be enforced in code, not by convention, because every publishing mechanism downstream inherits it.

MEASURED SET (orchestrator, /nix/var/nix/db/db.sqlite, 2026-08-10): 12,396 servable output paths holding 105,713 MiB; 6,769 of them carry a cache.nixos.org signature (53,854 MiB = 50.9% of bytes); 2,250 are locally built (ultimate) holding 35,870 MiB. So the publishable set is ~6,769 paths and roughly half the servable bytes are NOT publishable by construction.

TWO CAVEATS THAT MUST BE HANDLED, not just noted:
1. THE FILTER UNDER-PUBLISHES. Nix records a signature only on paths it SUBSTITUTED. A path rebuilt locally that is byte-identical to the public one has no local signature, so it is excluded even though it is public and perfectly safe to serve. The daemon can widen the set safely by consulting the upstream narinfos it ALREADY PROXIES: if upstream has a signed narinfo for this NarHash, the content is public regardless of how we obtained it. Implement the widening deliberately and say how it is bounded.
2. IT IS STILL A FINGERPRINT. Publishing which public packages you hold reveals your OS, toolchain, and roughly what you work on, even though no individual hash is secret. Not a blocker, but it must be stated in the README honest-limits and it is what leech mode (TASK-78) exists to switch off.

DO NOT let the filter become advisory. A publishing path that can emit an unsigned path is the privacy failure this whole design is built to avoid.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A single enforcement point decides publishability, and every publishing mechanism (DHT, tracker, gossip, announce-after-fetch) goes through it - shown by construction, not by each caller remembering
- [ ] #2 BITES BY MUTATION: attempt to publish a locally built (ultimate, unsigned) path and the attempt is REJECTED with a named failure; neutralize the filter and a test goes red. A local-only path must never reach any published record
- [ ] #3 The upstream-narinfo widening is implemented and bounded: a path we rebuilt locally but which upstream signs IS publishable, and the check that establishes that is stated and tested (do not simply trust the local sigs column)
- [ ] #4 The publishable set size is reported by the daemon (count and bytes) so an operator can see what they are exposing before enabling publication
<!-- AC:END -->
