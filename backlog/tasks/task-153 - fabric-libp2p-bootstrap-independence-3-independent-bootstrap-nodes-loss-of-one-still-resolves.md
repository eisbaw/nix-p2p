---
id: TASK-153
title: >-
  fabric-libp2p: bootstrap independence (>=3 independent bootstrap nodes; loss
  of one still resolves)
status: Done
assignee:
  - mped
created_date: '2026-08-12 07:55'
updated_date: '2026-08-12 19:00'
labels:
  - libp2p
  - fabric
  - dht
  - decentralized
  - hardening
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (AC#5). The cornerstone test uses a single bootstrap. Make >=3 independently operated bootstrap/routing nodes configurable (NodeConfig currently drives connectivity via explicit handle calls; add a bootstrap-set config + standard join). Prove an already-admitted healthy network keeps resolving content when ANY single bootstrap is lost, and that no single central service is required. Distinguish BootstrapOutage vs Partition in the Unavailable mapping where detectable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 >=3 independent bootstrap nodes are configurable and used to join
- [ ] #2 a multi-node test kills any one bootstrap and shows an already-admitted network still resolves an announced key
- [ ] #3 no single central service is required; BootstrapOutage vs Partition are distinguished where detectable
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done. >=3 independent bootstraps configurable + a standard join-through-the-set (join_bootstraps); a bootstrap-independence test PAIR proves an already-admitted network keeps resolving when any single bootstrap is lost. Commits 89cbb61 + 628773b + 5b87223.
Oracle (mutation-verified by orchestrator + a spawned mped-architect re-review that re-ran the mutations itself): the discrimination rests on the NEGATIVE CONTROL single_bootstrap_join_does_not_survive_its_only_bootstrap - forcing the provider onto all 3 bootstraps makes it Found (test fails as required); the positive test alone is non-discriminating (documented). AC#1/#2 met; AC#3 BootstrapOutage-vs-Partition is honestly documented as non-detectable at the read path (empty routing -> InsufficientRouting asserts neither).
Gate: build 0, lint 0, bootstrap_independence 2/2 stable x3, workspace --no-fail-fast 51/0. A pre-existing load-sensitive deadline flake (TASK-173, fabric-iroh/daemon - unrelated crates) surfaces under concurrent workspace load; both suspects pass in isolation. Filed TASK-174 (raise InsufficientRouting from total-routing count to a near-key query-stats bar).
<!-- SECTION:NOTES:END -->
