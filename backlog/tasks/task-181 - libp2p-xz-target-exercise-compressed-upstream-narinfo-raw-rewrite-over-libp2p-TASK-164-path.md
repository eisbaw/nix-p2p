---
id: TASK-181
title: >-
  libp2p xz target: exercise compressed-upstream-narinfo -> raw rewrite over
  libp2p (TASK-164 path)
status: To Do
assignee: []
created_date: '2026-08-12 23:03'
updated_date: '2026-08-18 06:51'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
  - subsumed
dependencies:
  - TASK-179
  - TASK-247
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The libp2p e2e targets are all already-raw (`lib`), so the compressed->raw narinfo rewrite (TASK-164: a peer serves the RAW nar while the upstream narinfo declares Compression: xz, and the daemon rewrites FileHash/FileSize/Compression to raw so real Nix accepts it) is NOT exercised on the libp2p path. S6 covers it on iroh; the DYNAMIC libp2p RawServeDecision (daemon/src/source_libp2p.rs) that mirrors the static iroh coupling is therefore not e2e-exercised for a compressed target.

DO: add an S7 arm whose target has an xz-compressed UPSTREAM narinfo (e.g. reuse the `app` fixture which is xz, 260 B on the wire, per check-fixtures) served RAW by the libp2p provider P and accepted by real Nix (byte-identical NarHash, 0 upstream NAR egress). Can extend scenario_s7_libp2p and/or scenario_s7_libp2p_netns with an xz target. Watch the NarSize-vs-FileSize unit trap. Filed from TASK-179 (secondary, out of reach this cycle); TASK-161 notes also flag it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Close this task as satisfied-by only after TASK-247 records the exact commit and machine report proving both the positive xz-narinfo to raw-peer real-Nix hit and the compressed dead-provider fallback, with separate NarSize/FileSize/peer/cache units, signed NarHash, provider/requester socket evidence, and upstream-byte contrast. No separate implementation is permitted.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Do not implement separately. TASK-247 AC#3/#4/#9 own the conventional compressed-upstream positive raw-peer hit, compressed dead-provider fallback, and any root fix. Close TASK-181 only as satisfied-by with TASK-247 commit/report evidence matching its sole AC.
<!-- SECTION:NOTES:END -->
