---
id: TASK-80
title: 'REAL NETWORK: Iroh and BitTorrent raw/compressed across NAT and real uplinks'
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
updated_date: '2026-08-14 21:48'
labels:
  - wave-2b
  - deferred-pending-202
dependencies:
  - TASK-45
  - TASK-70
  - TASK-89
  - TASK-99
  - TASK-119
  - TASK-121
  - TASK-125
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Run the comparative backends outside the single-host testbed after Stage A and both codec implementations. Use real machines on distinct networks, at least one behind NAT and one constrained residential-class uplink. Exercise Iroh raw/compressed and BitTorrent raw/compressed-or-recorded-no-go with their operational discovery paths and no per-content locator injection. Record topology and third-party infrastructure precisely; this evidence feeds Stage B and may show that a backend or public-sharing mode is not useful.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 At least three real hosts on distinct networks, including a NATed node and a constrained residential-class uplink, complete real Nix substitutions through Iroh and BitTorrent with no peer/content locator injection.
- [ ] #2 Raw/compressed arms run under matched workload/order and record socket wire bytes, NarSize, full-build latency, TTFB, CPU/RAM/disk/fds, provider upload and upstream egress; unsupported cells remain explicit.
- [ ] #3 Iroh records direct/hole-punched/relay and DNS/pkarr/DHT/tracker dependencies; BitTorrent records tracker/Mainline bootstrap, inbound reachability and client/server participation.
- [ ] #4 Residential-uplink viability receives a measured answer for serving and consuming, including concurrency and data-cap implications; datacenter-to-datacenter results cannot stand in for it.
- [ ] #5 NAT failure, relay/tracker/bootstrap outage, holder churn and client-only/leech modes have bounded S2 behavior and privacy/control-traffic observations.
- [ ] #6 The report places real-network results beside loopback/shaped results, states ranking changes and limitations, and carries manifest/config/code/topology hashes into TASK-122.
- [ ] #7 Real-network scenarios are development/training-only and cannot generate/read holdout IDs, seeds or topologies; an access bite fails before any network trial starts.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
