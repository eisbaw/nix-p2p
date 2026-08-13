---
id: TASK-166
title: >-
  Iroh relay evidence: measure real connect duration; stop clamping the deadline
  oracle
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-12 14:13'
updated_date: '2026-08-13 04:25'
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
F1 plan: (1) iroh_relay_evidence_peer.rs run_connect: Instant around timeout(deadline, endpoint.connect), inject unclamped connect_ms (pure connect time, before drive_connected) into the connect outcome JSON. (2) harness run_arm: record connect_ms UNCLAMPED as the gated timing; elapsed_ms becomes informational+unclamped. (3) finalizer validate_arm: gate connect_ms<=DEADLINE+GRACE, drop the elapsed clamp/gate; require connect_ms for the 7 network arms (wrong-url is config-time, no connect). (4) schema: add connect_ms (gated, max 11000), relax elapsed_ms (drop max). Prove bite: connect_ms=11001 -> finalizer FAILS.
<!-- SECTION:NOTES:END -->
