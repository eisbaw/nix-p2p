---
id: TASK-87
title: 'IROH HARNESS: 10+ real Nix nodes with operational peer and content discovery'
status: To Do
assignee: []
created_date: '2026-08-10 05:55'
updated_date: '2026-08-10 22:59'
labels:
  - wave-2b
dependencies:
  - TASK-54
  - TASK-57
  - TASK-58
  - TASK-60
  - TASK-83
  - TASK-86
  - TASK-89
  - TASK-99
  - TASK-100
  - TASK-101
  - TASK-103
  - TASK-114
  - TASK-115
  - TASK-116
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build the production-shaped Iroh testbed before any BitTorrent implementation. Run at least ten containers, each a real Nix client and daemon supplying from /nix/store on the persistent shared Iroh endpoint. Nodes receive no peer addresses or per-content claims. Node discovery plus tracker discovery must find dialable holders; TASK-126/103 global DHT runs only if supported and otherwise remains explicit unsupported; bounded hold-query probes only named candidate NodeIds from recorded sources. The harness is parameterized, trustworthy and keeps deterministic offline controls.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 N>=10 containers complete real substitutions of a wide real closure over Iroh with no iroh-peer or p2p-claim injection; N, discovery profile and holder distribution are parameters.
- [ ] #2 Provider-side bytes and Nix gate-2 prove every peer transfer; a corrupt-holder bite fails the build/path check, and a dead mechanism is unavailable rather than a clean miss.
- [ ] #3 Per transfer the trace records requester, privacy-safe provider token, transport/codec, discovery mechanism, wire bytes, NarSize, wall clock and fallback; unknown resource readings invalidate the run.
- [ ] #4 Concurrency and topology are measured rather than assumed, disk headroom fails fast, and concurrent harness runs cannot tear down one another.
- [ ] #5 The same manifest can select raw or negotiated-compressed Iroh without changing workload/topology, enabling TASK-88's paired measurement.
- [ ] #6 Tracker discovery is proven; global DHT is proven only when TASK-126/103 mark it supported and otherwise appears as evidenced unsupported. Direct hold-query records its candidate source (LAN, prior rendezvous, tracker/DHT) and its non-global coverage limitation; disabling each selected source restores upstream behavior.
<!-- AC:END -->
