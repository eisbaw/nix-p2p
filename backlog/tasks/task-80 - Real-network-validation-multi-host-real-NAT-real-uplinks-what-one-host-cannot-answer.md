---
id: TASK-80
title: >-
  Real-network validation: multi-host, real NAT, real uplinks (what one host
  cannot answer)
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
updated_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies:
  - TASK-73
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Every measurement in this project so far ran on ONE host: containers in podman pods, iroh endpoints bound to loopback with the relay DISABLED and no discovery, peer swarms as processes, and the only 'WAN' is TASK-63's testproxy shaping (which models service latency and egress rate, NOT a link - no slow start, no receive-window-over-RTT ceiling, so the bandwidth-delay product is absent by construction). TASK-70 shapes the peer link synthetically but is still one host.

This matters because the PRD's value thesis is explicitly about the real world: 'peers must actually beat or usefully supplement a global CDN as a byte source. Residential uplinks, thin seeders, and leech opt-outs all argue against'. And TESTING.md S5 forbids claiming emergent network effects from small-N local sweeps. So the two biggest open questions in the project - does DHT discovery work at swarm scale, and are residential uplinks a viable byte source - are structurally unanswerable by the existing testbed.

This task is the honest bridge: run the thing between real machines on real networks and report what changes. Expect the loopback rankings to move - TASK-64 established the peer transport is CPU-bound at ~204 MB/s on loopback doing ~13x TCP's CPU work per byte, which is a zero-RTT regime; a real link is receive-window-over-RTT bound instead, an entirely different binding constraint that no arm has touched.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The daemon runs on >=2 real hosts on a real network (at least one behind NAT) and serves a real nix build peer-to-peer; whether holepunching succeeded or the relay was used is RECORDED, not assumed
- [ ] #2 The headline testbed numbers are re-measured on real hosts and reported next to their loopback counterparts: offload, peers-on vs peers-off latency, throughput, RAM. Where the ranking changes, say so plainly
- [ ] #3 The residential-uplink question gets a measured answer or an explicit 'still unanswered and here is why' - do not let a datacenter-to-datacenter run stand in for a home uplink
- [ ] #4 PRD honest-limits updated with what real-network testing confirmed, refuted, or left open
<!-- AC:END -->
