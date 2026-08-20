---
id: TASK-283
title: >-
  Discovery-latency measurement: build the measure-discovery-latency scenario +
  mDNS/kad integer-ms instrumentation (fix the dangling just discovery-latency
  recipe)
status: Done
assignee: []
created_date: '2026-08-20 14:54'
updated_date: '2026-08-20 15:55'
labels:
  - measurement
  - testing
dependencies:
  - TASK-272
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS value-measurement item, now enabled by TASK-272 (the composite RUST_LOG subscriber). At HEAD the just discovery-latency recipe (Justfile:363) runs --only measure-discovery-latency but that scenario DOES NOT EXIST, there is NO mDNS/kad discovery-latency instrumentation, and evidence/task-272/ + the docs/profiling.md discovery-latency section reference numbers that were never produced. Answers PRD risk-3 (discovery latency, seconds-scale, could dominate small-package fetches and flip the peer-vs-CDN verdict).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Instrument the shipped discovery path to emit INTEGER-millisecond latencies via tracing (no floats): mDNS peer-discovery elapsed + kad get_providers elapsed, labelled with provenance (which node, which query)
- [x] #2 Implement the measure-discovery-latency e2e scenario (reuse the zero-bootstrap mDNS topology + RUST_LOG=info passthrough into containers) that drives a real discovery + captures the integer-ms numbers to evidence/task-272/ with the raw daemon logs; the just discovery-latency recipe runs it green (no longer dangling)
- [x] #3 Report the captured numbers (mDNS + kad, integer ms, provenance-labelled) in docs/profiling.md; state the container/loopback caveat (real-network discovery latency is TASK-268/237/282, not this containerized floor)
- [x] #4 Bite: the scenario fails/nulls if the instrumentation or the composite RUST_LOG subscriber is removed (proves it measures the real path, not a hardcoded value)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-283 delivered (commit 12895be), LIGHT self-gate green.
AC#1 instrumentation: fabric-libp2p/src/swarm.rs emits two tracing::info! markers on the shipped path - DISCOVERY-LATENCY-MDNS (mDNS time-to-first-peer, once per node, anchored at worker start) and DISCOVERY-LATENCY-KAD (kad get_providers wall-clock, per walk, anchored at issue). Integer u64 ms via as_millis+try_from (no floats). Provenance: local PeerId, discovered peer/content key. Surfaces under RUST_LOG=info via the TASK-272 composite subscriber.
AC#2 scenario: scripts/e2e_harness.py measure-discovery-latency reuses the zero-bootstrap mDNS topology; new RUST_LOG passthrough (Libp2pMdnsTopology.daemon_env -> podman -e on the daemon containers). Drives a real fetch, re-derives integers from RAW daemon logs, writes evidence/task-272/discovery-latency.json + lp-provider.log + lp-consumer.log. just discovery-latency runs GREEN (exit 0, 5/5 checks).
AC#3 report: docs/profiling.md new Discovery-latency section with the captured numbers + the container/loopback-floor caveat (real-network latency is TASK-268/237/282).
AC#4 bite PROVEN: dropped the RUST_LOG passthrough -> no markers -> mdns_ms=[] kad_ms=[] -> both assertions RED (scenario exit 1) while the driving fetch STILL completed, so the RED attributes to the lost measurement not a broken path. Mutation restored.
Captured (one run, CONTAINER/LOOPBACK FLOOR): mDNS first-peer 1 ms (provider .11) / 610 ms (consumer .10, startup-ordering-bound); kad get_providers 0 ms x6 (sub-ms on loopback, integer-floored - provider address already in the k-buckets via mDNS add_address). Honest limitation: this floor does NOT capture WAN RTT / multi-hop DHT; kad 0 ms means <1 ms once the peer is known, not free on a real network.
Gate: cargo test -p fabric-libp2p -p daemon-libp2p -p daemon green (67 suites, 0 failed); cargo fmt --all --check green; ruff check scripts green; nix-instantiate --parse nixos/nix-p2p.nix OK; disk 66G at end. Status left for orchestrator (not marked Done); orchestrator owns the qa/mped/codex review gate.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Real discovery-latency numbers captured on the container/loopback floor (integer ms, no floats, real-path instrumentation in fabric-libp2p/src/swarm.rs; RUST_LOG passthrough into containers via Libp2pMdnsTopology). mDNS first-peer: provider 1ms, consumer 610ms (startup-ordering-bound, not multicast); kad get_providers 0ms x6 (sub-ms once peer known). Bite PROVEN at real-path level (drop the RUST_LOG passthrough -> no markers -> parser nulls -> RED, while the driving fetch still completes = attributes to lost measurement not broken discovery). just discovery-latency 5/5 green; NOT in the fast just e2e gate (opt-in instrument, +46s to e2e-full). docs/profiling.md updated. HONEST FLOOR: kad 0ms = <1ms once peer known, NOT free on a real network; real-WAN RTT + multi-hop unmeasured -> TASK-268/237/282. Value-thesis read: LAN discovery is cheap, reducing PRD risk-3's seconds-scale concern on the container floor. Fixes the dangling just discovery-latency recipe. Commit 12895be.
<!-- SECTION:FINAL_SUMMARY:END -->
