---
id: TASK-94
title: >-
  Measure the peer-wins inequality: peers ship raw NAR at 0.278x upstream's wire
  efficiency, so no size threshold exists below ~75 MB/s peer upload
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-10 09:10'
labels:
  - wave-2b
dependencies:
  - TASK-70
  - TASK-80
  - TASK-64
  - TASK-52
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE CHEAP DISPROOF. Every discovery design in the packet justifies its lookup latency by amortising it against a download the peer saves. That argument omits the peer transfer term, and correcting it may remove the justification for the entire discovery layer.

MECHANISM. Peers serve the RAW uncompressed NAR: daemon/src/rewrite.rs rewrites the narinfo to `Compression: none`, `FileHash == NarHash`, `FileSize == NarSize` (REWRITE_ALLOWLIST at rewrite.rs:97; asserted at daemon/tests/narinfo_rewrite.rs:170 and :232). cache.nixos.org serves xz. I sampled 20 random cache.nixos.org-signed paths over 10 MiB from the live cache on 2026-08-10: aggregate FileSize/NarSize r = 0.278, median 0.216, min 0.090, max 0.894, 19 xz + 1 zstd. So for the same store path the peer moves ~3.6x the wire bytes upstream moves.

THE ARITHMETIC. Peer wins iff S/B_peer + L + D_dial < S*r/B_up. The S terms require 1/B_peer < r/B_up, i.e. B_peer > B_up/r = 21/0.278 = 75.5 MB/s = 604 Mbit/s SUSTAINED UPLOAD, before any latency is counted. Below that threshold the inequality has no solution at any S, and the deficit GROWS with S. Worked on the p100 path (3186 MiB): upstream ~886 MiB compressed / 21 MB/s = 44 s; a peer at 100 Mbit/s = 268 s (6x loss); at 300 Mbit/s = 89 s (2x loss). This inverts the fat-tail thesis — the 151 paths over 100 MiB are the maximum-LOSS set, not the maximum-gain set — and removes the amortisation defence for a 647 ms DHT lookup generally.

TRAPS. (1) The 21 MB/s upstream figure is SINGLE-STREAM against a CDN; Nix runs parallel substitutions (max-substitution-jobs), so aggregate upstream is higher and the threshold is worse. (2) The 204-210 MB/s peer number is LOOPBACK and CPU-bound — TASK-64 records iroh at 210 MB/s where HTTP does 758 MB/s on the same wire (3.6x deficit), and TASK-70 already states every peer number in this repo is a loopback upper bound. Do not reuse it. (3) NarSize is uncompressed and FileSize is the compressed transport size; they are different units and this project has conflated them three times already. (4) The PRD's Addressed-unit row already says "~3x wire bytes until per-connection zstd (a policy surface, not frozen)" — so a transport-layer codec is sanctioned, but bao/BLAKE3 verification is over the RAW NAR and TASK-48 froze RawNarV1, so compression must be a per-connection transport codec, never a change to the addressed unit.

WHAT FALSIFIES IT. If measured median B_peer between real WAN hosts exceeds 75.5 MB/s, or if per-connection zstd on the iroh leg brings effective r_peer to within ~1.2x of upstream's r, the amortisation argument is restored and TASK-73/TASK-93's size-gating direction lives. Otherwise the project's value thesis must be restated as byte-offload / LAN / offline operation rather than latency, and the PRD's <10% p95-latency kill criterion becomes the binding constraint rather than the 20% egress cut.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 r = FileSize/NarSize is measured over >=200 cache.nixos.org-signed paths spanning all size deciles, reported as an aggregate AND per-decile, with the Compression field recorded per sample. BITE: re-run against a fixture narinfo whose FileSize is set equal to NarSize — the report must classify that sample as 'uncompressed upstream' and exclude it from the aggregate, not silently average r=1.0 in.
- [ ] #2 B_peer is measured between two hosts on DIFFERENT physical networks with different ISPs, at >=3 NAR sizes including one >=1 GiB, reporting sustained MB/s at the socket. BITE: the harness must refuse to run when both endpoints resolve to the same host or to loopback — demonstrate the refusal firing by pointing both ends at one machine (this is the TASK-70 / TASK-80 failure mode).
- [ ] #3 The report computes and prints the break-even size S* from the measured r, B_up and B_peer, and when 1/B_peer >= r/B_up it prints 'NO SIZE THRESHOLD EXISTS' instead of a number. BITE: feed it B_peer=10 MB/s, r=0.278, B_up=21 MB/s and confirm it prints the no-threshold verdict; a version that returns a large finite S* has divided by a negative denominator and must fail.
- [ ] #4 A per-connection zstd prototype on the iroh leg is measured end-to-end and reported as an effective r_peer. BITE: r_peer must be computed from byte counters AT THE SOCKET under the TASK-52 counting rule, not inferred from a compressor's reported ratio — verify by confirming the socket-counted bytes exceed the compressor-reported bytes by the QUIC/framing overhead.
- [ ] #5 The task closes with a written go/no-go recorded in the tracker: if measured median B_peer < B_up/r_effective, the record must state that latency-amortised discovery is disproved for WAN peers and name which backlog items are thereby invalidated (at minimum the size-gating direction in TASK-73 and the amortisation argument in TASK-93). BITE: TASK-73's key-derivation freeze must be blocked on this record via a tracker dependency edge, verified by the edge existing, not by convention.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY: TASK-99 is the FIX for the asymmetry this task measures. Sequence them deliberately - measure the inequality first (it is the honest baseline and the cheap disproof), but do NOT conclude 'peers cannot win' from a measurement taken with compression OFF. The PRD reserved per-connection zstd at round 3 as a policy surface; the 3.6x is a deferred feature gap, not a property of the design.
<!-- SECTION:NOTES:END -->
