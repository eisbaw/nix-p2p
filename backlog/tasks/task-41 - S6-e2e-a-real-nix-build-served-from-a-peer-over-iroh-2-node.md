---
id: TASK-41
title: 'S6 e2e: a real nix build served from a peer over iroh (2-node)'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 00:10'
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

FROM task-39 (commit 120463e): the real two-endpoint iroh fetch works end-to-end on loopback (relay disabled, no discovery) - see daemon/tests/iroh_transport.rs. S6 wiring: node B = IrohProvider (seed the real NAR from nix-store --dump / task-50 index), node A registers IrohTransport in the TransportRegistry the TransportNarSource holds and resolves the signed NarHash -> claim -> fetch. Both gates proven: gate1 BLAKE3/bao in the transport, gate2 sha256==NarHash is Nix's on substitute. For a REAL nix build served from a peer, feed A's daemon the peer's IrohPeerAddr via task-40 discovery. NOTE: nix flake check would run the loopback iroh test inside the build sandbox (unconfirmed); S6's harness runs outside the sandbox so it is unaffected.

CRITICAL from codex task-39 review - S6 addressing: task-39's iroh test uses bind_addr(127.0.0.1:0) direct-loopback with relay DISABLED, which is genuine p2p but LOOPBACK-ONLY. For the 2-node CONTAINER S6, node A must reach node B across container network namespaces - so S6 must (a) bind/publish real inter-container-reachable direct addresses (not 127.0.0.1; and note iroh leaves a default IPv6 wildcard bind), or run a relay/rendezvous, or supply externally-reachable addrs; AND (b) VERIFY the iroh fetch works inside the nix/container sandbox netns (iroh netmon under sandbox is unconfirmed - if it fails, that's a real S6 blocker to solve, not fake around). Also: task-49 narinfo-rewrite is REQUIRED for the client to accept the peer-served raw NAR; task-40 discovery for A to find B; task-51 safety envelope for the S2 kill-node-B fallback.
<!-- SECTION:NOTES:END -->
