---
id: TASK-166
title: >-
  Iroh relay evidence: measure real connect duration; stop clamping the deadline
  oracle
status: To Do
assignee: []
created_date: '2026-08-12 14:13'
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
