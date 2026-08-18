---
id: TASK-247
title: E2E test of real nix-daemon substitution concurrency over libp2p
status: To Do
assignee: []
created_date: '2026-08-17 22:11'
updated_date: '2026-08-18 06:55'
labels:
  - e2e
  - performance
  - nix-daemon
  - concurrency
  - libp2p
  - measurement
dependencies:
  - TASK-18
  - TASK-57
  - TASK-62
  - TASK-180
  - TASK-194
  - TASK-207
  - TASK-219
references:
  - 'https://nix.dev/manual/nix/2.35/command-ref/conf-file'
  - 'https://bmcgee.ie/posts/2023/12/til-how-to-optimise-substitutions-in-nix/'
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The canonical E2E paths pin max-substitution-jobs and http-connections to 1 for exact counting. TASK-18 proves requested values land, but its 3-4 path workload cannot expose an independent concurrency effect. Using TASK-57 wide_closure after TASK-62 streaming and TASK-180 symmetric socket evidence, test whether a real multi-user Nix daemon overlaps nix-p2p discovery/peer transfer latency under serial, isolated, default, and high knob arms. Positive or evidenced no-effect outcomes are valid; only positive preregistered evidence may justify an operator recommendation. Use standard daemon-owned nix.settings, keep hedging off/v2 accounting, preserve byte identity and additive fallback, and feed the result to TASK-237.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A real multi-user NixOS nix-daemon with nix-p2p as its only configured substituter realises a cold closure of at least 128 independently substitutable paths through the shipped libp2p path; provider identity comes from kad discovery with no per-content or provider-address injection.
- [ ] #2 The matrix includes serial max-substitution-jobs=1 with http-connections=1; isolated controls 1 with 25 and 16 with 1; Nix defaults 16 with 25; and high 128 with 128. Daemon-owned configuration is applied before daemon start and read back exactly; observed behavior proves the daemon used it rather than merely parsing client flags.
- [ ] #3 Every arm realises every path with signed NarHash equality and no partial object or deadlock while fd RSS and in-flight bounds are measured. A mixed peer-hit peer-miss and dead-provider arm proves concurrent fallback without head-of-line blocking. At least one dead-provider object starts as a conventional compressed upstream NAR whose narinfo is rewritten to raw; an already-raw fixed-point-only escape does not satisfy this criterion.
- [ ] #4 Any serialization resource or compressed-to-raw fallback failure found in nix-p2p is fixed at its owning boundary and protected by a biting regression test. No workaround hidden queue test-only provider injection or raw-only substitution of the required compressed arm is accepted.
- [ ] #5 A canonical just e2e-substitution-concurrency recipe runs the scenario and is included in the appropriate full or wave-boundary E2E gate. Its machine-readable report records effective knob values overlap request counts upstream bytes wall times and resource maxima; TESTING.md documents measured results and an evidence-backed operator recommendation without blindly hardcoding 128.
- [ ] #6 Timestamped nix-p2p HTTP, peer discovery, and peer transfer intervals test max-substitution-jobs and http-connections independently. Each axis either shows the preregistered overlap effect with its named low arm binding at one, or produces a non-vacuous evidenced result that this Nix/version/topology does not expose an independent effect; config readback or process count alone never passes.
- [ ] #7 Under deterministic shaped RTT/fixed peer delay, preregistered integer/rational overlap, wall-time, and A/A bounds decide whether a parallel arm hides latency. A serializing mutation must fail the positive oracle. An evidenced no-effect result is valid task completion but forbids a high-concurrency recommendation and is fed honestly to TASK-237.
- [ ] #8 All TASK-247 arms use net-upstream-egress-v2 with hedging explicitly disabled and assert that no hedge request/provenance occurs. Hedge/value accounting begins only after TASK-52 freezes v3; TASK-247 cannot emit hedge-policy evidence.
- [ ] #9 The real-Nix matrix includes both a positive xz-compressed upstream narinfo served as a raw peer NAR with exact rewrite/NarHash and zero upstream NAR payload, and a compressed dead-provider object that falls back upstream correctly. NarSize, FileSize, peer raw application bytes, and cache compressed-wire bytes remain separate.
- [ ] #10 Before execution, the machine-readable manifest freezes integer/rational thresholds for request/stream overlap, TTFB, total wall time, RSS/inflight/fd maxima, repeated-run noise, and A/A equivalence. Missing thresholds or thresholds chosen after results invalidate the arm.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Land or reuse TASK-57 wide-fanout fixtures. 2. Add a real nix-daemon NixOS E2E topology over the shipped libp2p path. 3. Instrument request and peer-stream intervals plus resource and egress counters. 4. Execute the factorial knob matrix under deterministic latency and prove the red-green serialization bite. 5. Fix any real concurrency bottleneck, integrate the just gate, and feed evidence into TASK-237.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Current-product audit: the old scale sweep couples knobs over only 3-4 paths and proves readback, not independent request/stream overlap. TASK-57 supplies only the formal wide_closure; TASK-62 removes whole-NAR store-and-forward; TASK-180 supplies symmetric provider/requester application and interface evidence. This task runs v2 with hedging explicitly disabled, tests serial/isolated/default/high daemon-owned settings, freezes rational thresholds before results, and accepts an honest evidenced no-effect result without recommending higher defaults. It owns both the positive xz-upstream-narinfo to raw-peer real-Nix hit, the compressed dead-provider fallback, and any owning-boundary root fix; TASK-181 closes only from this task commit/report evidence. TASK-14 may reuse the result for later broad soak.
<!-- SECTION:NOTES:END -->
