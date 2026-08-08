---
id: TASK-39
title: 'iroh whole-NAR transport (provider + client, BLAKE3 hash-gated)'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
labels: []
dependencies:
  - TASK-38
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
<!-- AC:END -->
