---
id: TASK-298
title: >-
  Measure the real value thesis: peer zstd /nar4 transport vs CDN xz transport
  (real-public peer path)
status: To Do
assignee: []
created_date: '2026-08-21 09:21'
labels:
  - testing
  - measurement
  - follow-up
dependencies:
  - TASK-282
  - TASK-168
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-282 AC#3 built the rigorous fail-closed measurement tier + measured the CDN compression ratio (real cache.nixos.org, 15 paths x5 runs, verified TLS) + a peer EXISTENCE proof (byte-identical fetch over a KVM-NAT VM). But the actual VALUE THESIS - peer-vs-CDN TRANSPORT bytes - stays UNPROVEN (verdict.json peer_vs_cdn_transport.measured=false). codex caught that the shipped /nar4 peer transport is zstd-COMPRESSED on the wire (a 4MB NAR = ~5.8KB), so comparing uncompressed NarSize to CDN-compressed was the wrong quantity. The honest comparison (peer-zstd vs CDN-xz) is near-parity/link-dependent per the shaped-link table. Blocked on a REAL-PUBLIC peer path: a NixOS VM is hermetic, so a real peer-vs-CDN-over-the-internet number needs TASK-168's NAT/relay work (coordinate 207/247).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The finalizer measures the peer's ACTUAL on-the-wire zstd /nar4 transport bytes (not uncompressed NarSize) across the same real store paths as the CDN arm, and emits a peer-transport-vs-CDN-transport verdict (float-free, magnitude-bounded, provenance-labelled) - measured=true.
- [ ] #2 The peer arm runs over a real-public (or genuinely reachable multi-host, not hermetic-VM) path so the peer-vs-CDN number reflects a real network, incl. discovery latency; value_thesis resolves to a supported supplement/parity/beat finding with |delta| bounds.
<!-- AC:END -->
