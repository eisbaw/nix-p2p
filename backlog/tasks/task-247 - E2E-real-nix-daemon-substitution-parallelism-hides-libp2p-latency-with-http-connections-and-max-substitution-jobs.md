---
id: TASK-247
title: >-
  E2E real nix-daemon substitution parallelism hides libp2p latency with
  http-connections and max-substitution-jobs
status: To Do
assignee: []
created_date: '2026-08-17 22:11'
updated_date: '2026-08-17 22:53'
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
  - TASK-194
  - TASK-207
references:
  - 'https://nix.dev/manual/nix/2.35/command-ref/conf-file'
  - 'https://bmcgee.ie/posts/2023/12/til-how-to-optimise-substitutions-in-nix/'
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The canonical E2E paths pin max-substitution-jobs and http-connections to 1 for exact counting. TASK-18 sets and reads back 1, 16, and 128, but its 3-4 path workload explicitly cannot demonstrate a concurrency effect. TASK-14 is a broad far-future cross-backend soak blocked by optional work. Build a current-product, libp2p-specific E2E using one real multi-user Nix daemon and the TASK-57 wide-fanout closure. Prove that standard Nix daemon substitution and HTTP concurrency can overlap nix-p2p discovery and peer transfer latency without weakening byte identity or additive fallback. Use standard nix.settings rather than inventing duplicate proxy knobs. Do not adopt 128 as a production default without evidence. Feed the resulting evidence and recommendation into TASK-237.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A real multi-user NixOS nix-daemon with nix-p2p as its only configured substituter realises a cold closure of at least 128 independently substitutable paths through the shipped libp2p path; provider identity comes from kad discovery with no per-content or provider-address injection.
- [ ] #2 The matrix includes serial max-substitution-jobs=1 with http-connections=1; isolated controls 1 with 25 and 16 with 1; Nix defaults 16 with 25; and high 128 with 128. Daemon-owned configuration is applied before daemon start and read back exactly; observed behavior proves the daemon used it rather than merely parsing client flags.
- [ ] #3 Timestamped nix-p2p HTTP requests and peer discovery/fetch streams prove measured overlap. Defaults and high arms must exceed one concurrent substitution and one simultaneous cache connection. Pairwise isolated controls must show max-substitution-jobs=1 binding substitution overlap and http-connections=1 binding HTTP connection overlap; concurrency is never inferred from process count.
- [ ] #4 Under deterministic shaped RTT or fixed peer delay repeated runs with a preregistered integer-only noise rule show a parallel arm reduces total cold-realise wall time versus serial by a stated lower bound while preserving exact net-upstream-egress accounting. An A/A control passes and a mutation forcing serialization makes the latency-hiding oracle fail.
- [ ] #5 Every arm realises every path with signed NarHash equality and no partial object or deadlock while fd RSS and in-flight bounds are measured. A mixed peer-hit peer-miss and dead-provider arm proves concurrent fallback without head-of-line blocking. At least one dead-provider object starts as a conventional compressed upstream NAR whose narinfo is rewritten to raw; an already-raw fixed-point-only escape does not satisfy this criterion.
- [ ] #6 Any serialization resource or compressed-to-raw fallback failure found in nix-p2p is fixed at its owning boundary and protected by a biting regression test. No workaround hidden queue test-only provider injection or raw-only substitution of the required compressed arm is accepted.
- [ ] #7 A canonical just e2e-substitution-concurrency recipe runs the scenario and is included in the appropriate full or wave-boundary E2E gate. Its machine-readable report records effective knob values overlap request counts upstream bytes wall times and resource maxima; TESTING.md documents measured results and an evidence-backed operator recommendation without blindly hardcoding 128.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Land or reuse TASK-57 wide-fanout fixtures. 2. Add a real nix-daemon NixOS E2E topology over the shipped libp2p path. 3. Instrument request and peer-stream intervals plus resource and egress counters. 4. Execute the factorial knob matrix under deterministic latency and prove the red-green serialization bite. 5. Fix any real concurrency bottleneck, integrate the just gate, and feed evidence into TASK-237.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Repository audit at filing: scale_sweep currently couples both knobs as 1,1 / 16,16 / 128,128 over only three substitutable paths; it validates whole-client realise overlap, not NAR-request overlap, and only max-substitution-jobs participates in the validity check. TESTING.md instead freezes the normal middle arm as 16,25. testproxy request start/duration records plus its one-request-per-connection server provide the closest cache-connection overlap oracle. This task owns the focused current-libp2p proof; TASK-14 retains broad restart/fault/cross-backend soak and should consume rather than duplicate this result.

MPED review tightening: the dead-provider arm must include a conventional compressed upstream object whose narinfo is rewritten to raw. The current already-raw fixed-point fallback cannot stand in for that common case; if it exposes the known token/decompression gap then AC#6 owns the product root fix and biting regression. Defaults/high must prove both forms of overlap while each isolated arm is expected to pin its named dimension at one.
<!-- SECTION:NOTES:END -->
