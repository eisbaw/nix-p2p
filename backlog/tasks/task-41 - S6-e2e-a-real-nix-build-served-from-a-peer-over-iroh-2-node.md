---
id: TASK-41
title: 'S6 e2e: a real nix build served from a peer over iroh (2-node)'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-08 20:30'
labels: []
dependencies:
  - TASK-39
  - TASK-40
  - TASK-49
  - TASK-50
  - TASK-51
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The wave-2 CORE ACCEPTANCE SIGNAL (S6) and the decentralization PoC. Container harness (reuse task-5 Pod seam, extend to 2 daemon nodes each with an iroh transport): node B holds a fixture closure; node A's nix build resolves the NarHash, fetches the NAR from B over iroh, passes the NarHash gate, store byte-identical. The measurement (net-upstream-egress-v2) counts it as a VALID 0-egress offload crossing. cache.nixos.org/mock is NOT touched for the peer-served path (asserted by request counts).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Node A nix build completes with the NAR served by node B over iroh; S1 byte-identity holds; testproxy/mock upstream NAR egress == 0 for the peer-served path, PAIRED with a nonzero peer-served count (oracle-pairing)
- [ ] #2 Kill node B mid-transfer -> node A falls back to upstream and the build still succeeds (S2 through the p2p path)
- [ ] #3 Bite: a peer serving corrupted bytes -> build fails at the NarHash gate, no wrong bytes stored
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (S6 oracle hardening, qa#2/#5 + arch#7 + codex#6): (1) Add the WAVE-1 MANDATORY absent-before precondition + client nix-cache wipe (else 0 egress is vacuous - path already in store). (2) Ground the peer-served count at NODE B's iroh PROVIDER byte counter, NOT the daemon self-report (self-narration untrusted per wave-1). (3) Add a peers-OFF contrast arm proving the cache-egress channel reports FULL NAR bytes in THIS p2p harness (falsifies the 0). (4) 'cache untouched' is an OVERCLAIM - narinfo/NarSize still come from upstream in wave-2a; assert NAR-payload-egress==0 + narinfo egress as nonzero CONTEXT. (5) Corruption bite split (see task-39). (6) This task CONFIRMS the freeze of task-37 (claim+query) and task-48 (RawNarV1) - the interop event; deep-gated.
<!-- SECTION:NOTES:END -->
