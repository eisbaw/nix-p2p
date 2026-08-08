---
id: TASK-41
title: 'S6 e2e: a real nix build served from a peer over iroh (2-node)'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels: []
dependencies:
  - TASK-40
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
