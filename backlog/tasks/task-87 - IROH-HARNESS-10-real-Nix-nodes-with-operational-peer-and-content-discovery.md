---
id: TASK-87
title: 'IROH HARNESS: 10+ real Nix nodes with operational peer and content discovery'
status: To Do
assignee: []
created_date: '2026-08-10 05:55'
updated_date: '2026-08-11 20:08'
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
  - TASK-103
  - TASK-114
  - TASK-115
  - TASK-116
  - TASK-120
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build the production-shaped Iroh testbed before any BitTorrent implementation. Run at least ten containers each a real Nix client and daemon supplying from the Nix store on the persistent shared runtime under TASK-120 modes. Nodes receive no peer addresses or per-content claims. Passing TASK-103 decentralized exact-key content discovery and TASK-89 public node discovery are mandatory. LAN and bounded hold-query are separate enabled scenarios. Tracker and Mainline are optional comparison cells that do not block or qualify the Iroh harness.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 N>=10 containers complete real substitutions of a wide real closure over Iroh with no iroh-peer or p2p-claim injection; N, discovery profile and holder distribution are parameters.
- [ ] #2 Provider-side bytes and Nix gate-2 prove every peer transfer; a corrupt-holder bite fails the build/path check, and a dead mechanism is unavailable rather than a clean miss.
- [ ] #3 Per transfer the trace records requester, privacy-safe provider token, transport/codec, discovery mechanism, wire bytes, NarSize, wall clock and fallback; unknown resource readings invalidate the run.
- [ ] #4 Concurrency and topology are measured rather than assumed, disk headroom fails fast, and concurrent harness runs cannot tear down one another.
- [ ] #5 The same manifest can select raw or negotiated-compressed Iroh without changing workload/topology, enabling TASK-88's paired measurement.
- [ ] #6 Passing decentralized NAR-to-provider discovery is proven with tracker and LAN disabled. Direct hold-query records its bounded candidate source and non-global limitation; disabling each selected source restores upstream behavior without turning outages into MISS.
- [ ] #7 The manifest records exact TASK-120 configuration. LAN DNS pkarr relay hold-query and decentralized DHT mechanisms each have explicit enabled state. Optional tracker and Mainline rows run only when their artifacts exist and unsupported optional rows are never imputed or treated as Iroh qualification.
<!-- AC:END -->
