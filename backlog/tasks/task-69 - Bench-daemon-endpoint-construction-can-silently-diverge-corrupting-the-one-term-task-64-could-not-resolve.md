---
id: TASK-69
title: >-
  Bench/daemon endpoint construction can silently diverge, corrupting the one
  term task-64 could not resolve
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 14:59'
updated_date: '2026-08-11 03:21'
labels:
  - tech-debt
  - measurement
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY REVIEW during TASK-64. daemon/examples/iroh_throughput.rs's bare_endpoint() restates daemon/src/transport_iroh.rs's private bind_loopback_endpoint(), and provider_endpoint_addr() restates IrohProvider::addr(). They are byte-identical TODAY (verified), so there is no live error - which is exactly why this is worth filing rather than fixing in a hurry. The hazard is silent drift: every rung of the bench's subtraction ladder EXCEPT daemon_fetch runs on the bench's copy, and daemon_fetch runs on the daemon's. Any future divergence - transport config, congestion controller, initial MTU, keep-alive, relay mode - lands invisibly in the iroh_collect -> daemon_fetch difference, which is PRECISELY the term PRD entry 11 already flags as unresolved and swinging +-0.7 ns/B. PRD risk 10 is 'iroh API churn: accepted maintenance tax', so drift is expected rather than hypothetical, and this failure is silent rather than loud. NOT a DRY nit: the bench's central claim is 'raw QUIC on the SAME iroh Endpoint stack', and nothing mechanically holds that true. Options, cheapest first: (a) a #[doc(hidden)] pub re-export of bind_loopback_endpoint so the bench uses the daemon's own binder - but note the module deliberately keeps iroh opaque behind IrohPeerAddr so callers never touch the iroh crate, and this would breach that on purpose; (b) an assertion in the bench comparing the two endpoints' observable configuration; (c) accept and document. Whichever is chosen, the point is that a divergence must FAIL rather than quietly change a number.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The bench's raw-QUIC arms and the daemon's transport provably share one endpoint configuration, or a divergence between them fails loudly
- [x] #2 The chosen mechanism is proven by mutation: change the daemon's binder and watch the guard go red, restore and watch it go green
- [x] #3 If option (a) is taken, the deliberate breach of the 'callers never touch iroh' boundary is documented at the export site with its reason
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read TASK-69/TASK-115, PRD measurement constraints, TESTING contracts, README, recent history, and current daemon/benchmark endpoint code.
2. Introduce the smallest daemon-owned typed endpoint-construction contract so raw-QUIC and daemon-fetch arms cannot select divergent endpoint configuration.
3. Add a focused deterministic parity/mutation guard, demonstrate red under an intentional selected-config mutation, restore, and prove green.
4. Run focused checks plus nix develop -c just build, lint, test, e2e, and a bounded iroh-bench smoke; record exact evidence for review.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation started. Scope is limited to TASK-69 endpoint construction/parity and focused support. I will not mark acceptance criteria complete or move the task to Done; closure remains with the orchestrator after review.

Implementation evidence (2026-08-11):
- daemon/src/transport_iroh.rs now owns the typed MinimalIpv4LoopbackNoRelay profile, the daemon selector, the only Endpoint builder, and canonical Endpoint-to-EndpointAddr conversion. Provider and fetcher both select it.
- daemon/examples/iroh_throughput.rs has an independent benchmark selector, a compile-time equality assertion against the daemon selector, and routes every raw QUIC/raw Iroh endpoint plus provider address through the daemon-owned support seam. The hidden export documents the deliberate narrow Iroh-type boundary exception.
- Mutation bite, daemon side: temporarily changed only DAEMON_ENDPOINT_PROFILE port 0 to 1; the focused cargo test command failed deterministically with exit 101 / E0080 and message TASK-69: benchmark and daemon selected different Iroh endpoint profiles. Restored to port 0.
- Mutation bite, benchmark side: temporarily changed only BENCHMARK_ENDPOINT_PROFILE port 0 to 1; the same focused command failed deterministically with exit 101 / E0080 and the same named diagnostic. Restored to port 0.
- Restored focused check: nix develop -c cargo test --locked --example iroh_throughput tests::benchmark_endpoint_profile_matches_daemon -- --exact -> 1 passed, exit 0.
- Final-tree gates: nix develop -c just build -> exit 0; just lint -> exit 0; just test -> exit 0; just e2e -> exit 0, all 5 scenarios passed (75.4 s scenario time, including s6-p2p); just iroh-bench -> exit 0 on its fixed 3-size x 5-repeat grid, all raw-QUIC/raw-Iroh/daemon-fetch arms completed.
- e2e-full was not run: TASK-69 preserves the exact previous Minimal + relay-disabled + IPv4 loopback bind behavior and changes no serving/fetch semantics; the required fast e2e includes the real s6-p2p path.
- Honest profile limit found during review: MinimalIpv4LoopbackNoRelay does not mean fully offline or loopback-only. Pinned iroh retains its IPv6 default transport, port mapper, and net-report defaults. The name/docs state only the overrides actually selected; TASK-115 owns clear_ip_transports plus explicit loopback binds and explicit portmapper/net-report disablement for a genuine offline_test profile.

Architecture NO-GO correction (2026-08-11): swept all of daemon/src/transport_iroh.rs for stale loopback/offline claims, not only the cited line ranges. Corrected module-level relay/discovery scope plus public IrohProvider::spawn, socket_addrs, addr, and IrohTransport::spawn docs. They now state the exact selected overrides (Minimal preset, relay disabled, IPv4 default replaced by 127.0.0.1), explicitly retain pinned Iroh IPv6 wildcard/port-mapper/net-report defaults, forbid reading the profile as offline or loopback-only, explain that cross-process publishing filters unspecified sockets, and assign genuine offline isolation to TASK-115. Verification: nix develop -c just lint -> exit 0 (clippy all targets, cargo fmt check, independence and source-policy checks all green). No runtime behavior changed.

Final independent gate: qa-test-runner GO and mped-architect GO on transport SHA-256 00918f87ba2db28adfebcb07f1bf72d0c2ef2622b2b4d8985741d1f07ad91475 and benchmark SHA-256 c148302c8f80331a9fe6861dfbdfb7bb61f2f365a1e3dedfc3b43e37700cb53. Build/lint/test/e2e passed; E2E was 5/5 scenarios and 48/48 checks. The fixed 8/32/110 MiB x 5-repeat release Iroh benchmark completed every arm. Independent daemon-side and benchmark-side selector mutations failed at compile time, then the restored tree passed. Architecture stale-doc NO-GO was corrected and re-gated GO.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Centralized daemon and benchmark Iroh endpoint construction behind one daemon-owned typed profile/binder and one canonical bound-endpoint address conversion. Separate daemon and benchmark selectors are exhaustively compile-time guarded, with independent mutation proof on each side. The deliberately narrow hidden Iroh-type measurement seam is documented. Existing behavior is preserved and accurately described as IPv4-loopback override plus retained Iroh IPv6/portmapper/net-report defaults; TASK-115 owns genuine offline isolation.
<!-- SECTION:FINAL_SUMMARY:END -->
