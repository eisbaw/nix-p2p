---
id: TASK-35
title: >-
  Re-measure narinfo->nar gap against a REAL upstream (cache.nixos.org RTT), not
  loopback
status: To Do
assignee: []
created_date: '2026-08-08 17:30'
labels:
  - finding
  - wave-2
  - measurement
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FINDING from task-12 (J2 baseline read-out). The wave-1 narinfo->nar gap histogram was measured over LOOPBACK against a local mock origin: median ~0.5ms, p95 <0.9ms, max <2ms, every sample in the [0,10)ms bucket. On these numbers the prefetch window is structurally near-zero and a 1-4s DHT resolve (PRD risk 3) cannot be masked behind it. BUT loopback carries no real RTT: the real client->cache.nixos.org gap includes upstream RTT, TLS, CDN latency and client think-time between the narinfo GET and the NAR GET, plausibly opening a materially larger prefetch window. The wave-1 gap is therefore NOT a verdict that prefetch is dead - it says the prefetch-masking premise MUST be validated against a real upstream before the hedge/prefetch design is committed. Also: the instrument's gap-synthesis is only proven to bite for sub-second injected gaps (daemon 1000ms header_timeout ceiling, see task-33); multi-second real-gap fidelity is unvalidated. Directly feeds task-15 (wave-2 re-plan) and task-16 (checkpoint gap question).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A narinfo->nar gap is measured against a real upstream (cache.nixos.org or a latency-shaped proxy standing in for real RTT), reported next to the wave-1 loopback baseline so the two are comparable
- [ ] #2 The measured real-upstream gap is compared against the 1-4s DHT-resolve latency p2p must hide; the report states whether the prefetch window is real at real-upstream RTT (the wave-1 loopback answer was no, but loopback-limited)
<!-- AC:END -->
