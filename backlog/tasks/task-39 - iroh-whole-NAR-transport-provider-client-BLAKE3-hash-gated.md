---
id: TASK-39
title: 'iroh whole-NAR transport (provider + client, BLAKE3 hash-gated)'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
updated_date: '2026-08-08 21:22'
labels: []
dependencies:
  - TASK-38
  - TASK-48
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FIRST transport (owner: iroh first prio). A node runs an iroh-blobs PROVIDER serving its /nix/store NARs (rendered via nix-store --dump, addressed by raw-NAR BLAKE3) and a CLIENT that fetches a NAR by BLAKE3 from a peer NodeId. Every fetched blob is BLAKE3-verified by iroh incrementally AND the assembled NAR passes sha256==NarHash. Add iroh to Cargo.lock (daemon-only; testproxy stays std-only - independence guard). n0 relay dependence noted as a soft-centralization limit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Node B provides a fixture NAR; node A fetches it by BLAKE3 over iroh and it passes both the BLAKE3 (transport) and sha256==NarHash (trust) gates - byte-identical to the fixture
- [ ] #2 A corrupted/wrong blob from a lying provider fails the gate; no wrong bytes reach the store (bite)
- [ ] #3 iroh is a daemon-only dep; the independence guard still passes (testproxy does not gain iroh)
- [ ] #4 ALPN reconciliation (task-48 deep-gate finding 2): once iroh is a dependency, assert IROH_BLOBS_ALPN == iroh_blobs::ALPN (compile-time or test) and realign the constant to the pinned iroh version - the task-48 freeze deferred this cross-check here; a wrong ALPN must fail loud at connect, and the offer needs no format field (whole-NAR is always iroh Raw format)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION: (1) task-39 no longer DEFINES the addressed unit - it CONSUMES the frozen RawNarV1 from task-48 (dep added). (2) Corruption bite must be SPLIT (codex#6): (a) mutated bytes fail the BLAKE3 TRANSPORT gate; (b) a DIFFERENT valid NAR with its own valid BLAKE3 PASSES transport but fails the signed sha256==NarHash TRUST gate - test both, they are different gates.
<!-- SECTION:NOTES:END -->
