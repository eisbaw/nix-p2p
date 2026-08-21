---
id: TASK-293
title: 'Mainline join: standing gate for the AC#6 mechanism test + container-netns arm'
status: To Do
assignee: []
created_date: '2026-08-21 02:28'
labels:
  - hardening
  - test
  - follow-up
dependencies:
  - TASK-284
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-284 delivered the Mainline discover->dial->kad-join MECHANISM test (mainline_rendezvous_join.rs) but it is #[ignore]d, so no standing gate exercises the join path (mped M3). Also the literal AC#6 container-netns NAR-fetch arm was deferred (mped ruled the mechanism test + composition of proven s7/mdns scenarios sufficient for gating). Close both: (1) wire the ignored join test into a heavy/nightly gate so a regression is caught; (2) add a Libp2pMainlineTopology podman scenario (rendezvous-spike local-bootstrap + a public-share provider with a seed + a consume-only consumer given ONLY --libp2p-mainline-rendezvous) asserting the consumer fetches a NAR with 0 upstream egress and no --libp2p-bootstrap/--provider-addr in its argv.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The AC#6 Mainline join mechanism test runs in a standing (non-ignored / gated) suite so a regression reddens CI.
- [ ] #2 A container-netns scenario proves a fresh consumer given ONLY --libp2p-mainline-rendezvous discovers a peer via Mainline, joins, and fetches a NAR byte-identical with 0 upstream egress (no injected bootstrap/provider addr in argv).
<!-- AC:END -->
