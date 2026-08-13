---
id: TASK-166
title: >-
  Iroh relay evidence: measure real connect duration; stop clamping the deadline
  oracle
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 14:13'
updated_date: '2026-08-13 05:16'
labels:
  - iroh
  - evidence
  - relay
  - integrity
  - timing
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
F1 from TASK-142 DEEP gate (gate-breaking). elapsed_ms is container wall-clock (gate-release -> container exit: connect + endpoint.close + 3s exchange + podman teardown), clamped to min(v,11000). It measures the wrong quantity (not the 10s connect deadline) AND the clamp means the finalizer's elapsed>11000 oracle can never bite; 4 arms report exactly 11000 (true value >=11000 censored to schema max). Relay capability is fine (tokio 10s timeout fires); evidence-instrument honesty defect. Fix: measure connect duration with Instant around timeout(deadline,endpoint.connect) in daemon/src/bin/iroh_relay_evidence_peer.rs, inject connect_ms into outcome JSON; harness records connect_ms UNCLAMPED; finalizer gates connect_ms, drop the clamp; schema gains connect_ms, elapsed_ms becomes informational. MUST land before the iroh-relay-capability-v1 schema freezes and before TASK-89 uses the artifact as a passing gate. Needs image rebuild + routed re-run + re-finalize + re-gate (oracle bites by mutation).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
F1 DONE. Root cause: gated timing was container wall-clock elapsed_ms clamped to min(v,11000), so the finalizer's deadline oracle could never bite (4 arms censored to 11000). Fix (commit 009b26b): iroh_relay_evidence_peer.rs run_connect wraps Instant AROUND timeout(deadline,endpoint.connect).await and injects UNCLAMPED connect_ms (pure connect, measured before drive_connected/exchange/close) into the connect outcome; harness records connect_ms as the gated timing; finalizer gates connect_ms<=DEADLINE+GRACE(11000), requires it for the 7 network arms, drops the clamp; wrong-url is config-time (no connect_ms). elapsed_ms now informational+unclamped. Schema: connect_ms max 11000, elapsed_ms max dropped.
GOTCHA: measure ONLY around the timeout().await; keep the post-connect exchange + endpoint.close OUTSIDE the Instant window or elapsed_ms's bug recurs.
S1 (DEEP gate, tempered in 1c3cd41): connect_ms is bounded by the peer's OWN 10000ms connect timeout and is a peer self-report anchored by the git-blob-pinned binary; the finalizer 11000ms gate re-asserts the deadline (no longer clamps), not an independent latency bound. Documented as a limitation.
Real run r86596355: the 4 deadline arms report connect_ms=10000 (REAL, was censored 11000); elapsed_ms ~13100 unclamped; half-open connect_ms=3032 (fast connect, post-connect stall); relay-success 3030; direct-positive 1.
Oracle bite (wired self-test + on the real tree): connect_ms=11001 -> finalizer FATAL; a network arm missing connect_ms -> FATAL.
Gate: just lint green; cargo build -p daemon --features evidence-fixture green; cargo test --workspace 612/0; peer bin 8/8 (new connect_ms test); both python self-tests PASS. mped+qa reviewed. Part of the honest iroh-relay-capability-v1 artifact (verdict=pass, sha256=44c0ac94a6438d7fde7f94af897c1e994bea6e2782973fb32a505b7e724899ea, bound to 76ae1e7).
<!-- SECTION:NOTES:END -->
