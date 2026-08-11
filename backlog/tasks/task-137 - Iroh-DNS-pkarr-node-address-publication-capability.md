---
id: TASK-137
title: Iroh DNS/pkarr node-address publication capability
status: Done
assignee:
  - '@me'
created_date: '2026-08-11 06:00'
updated_date: '2026-08-11 16:07'
labels:
  - iroh
  - discovery
  - node
  - publication
  - pkarr
  - persistence
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement only the explicit default-off NodeId/address publication capability consumed by public Iroh discovery. Publish the stable TASK-115 NodeId and declared reachable direct/relay location fields to a configured DNS/pkarr namespace. Do not implement lookup, enable relay transport, publish content keys, select an operator profile, or run the combined connection journey. Emit a versioned pass|no_go capability artifact for TASK-89.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Publication is a separate typed default-off capability. Enabling it performs no NodeId lookup, content lookup, relay connection or LAN discovery; disabled/offline-test emits zero DNS/pkarr/publication packets. Source and packet mutations prove the boundary.
- [x] #2 The record schema documents NodeId/location fields, namespace/version, signer, recipients, TTL, sequence and withdrawal behavior and contains no NarHash, StorePath, closure membership or content inventory.
- [x] #3 Publication is monotonic and crash-safe: atomic local state, sequence/expiry comparison, idempotent refresh, withdrawal where supported, stale/replay rejection, restart recovery and corrupted-state fail-closed behavior. Concurrent restart/lost-update/rollback/expired-resurrection mutations bite.
- [x] #4 The authoritative run-unique namespace starts empty. Provider-daemon startup to current signed record visibility has a 10000 ms total deadline; refresh and withdrawal become visible within 5000 ms. Monotonic configured/observed timings allow at most 1000 ms scheduler grace and the clock starts before daemon startup.
- [x] #5 Wildcard/unspecified bind addresses are never published as reachable locations. Interface/address churn either publishes a newer reachable record or withdraws inside the bound; readers never accept an older sequence after the transition.
- [x] #6 External n0/public DNS/pkarr contact, accounts, credentials, cost or infrastructure require a named owner and explicit authorization. Otherwise only a locally operated routed service is used and evidence is labelled production-shaped.
- [x] #7 Emit iroh-node-publication-v1 verdict=pass|no_go with final tree/evidence/schema hashes and failed constraints. Ordinary fixable implementation/test defects remain failure; TASK-89 validates the artifact and propagates an evidenced no_go.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation started 2026-08-11 under phase3 after TASK-115 commit c724f86. Scope is publication only: explicit default-off signed Iroh DNS/pkarr node-location records, durable monotonic state, bounded visibility/withdrawal, locally operated routed evidence, and a versioned capability verdict. Lookup, relay transport, LAN discovery, content publication and operator policy remain outside TASK-137. Acceptance boxes stay open until implementation, full gates and independent review.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented the independently reviewed, default-off signed Iroh pkarr node-address publication capability. Implementation commit: 56e5bcae5fe12b85a625d4515241232815bc9d4c. Clean production-shaped routed evidence: evidence/task-137/r15d02a-9be2623d9e14; it proves zero packets and zero authority requests for default-off and both offline controls, plus signed startup, scheduled refresh, SIGTERM withdrawal, bounded timings, and exact publisher-to-authority capture. Focused committed tests and mutation gates separately prove address-churn handling, crash/restart recovery, stale/replay rejection, corrupted-state failure, and rollback/expired-resurrection defenses. Final artifact: artifacts/iroh-node-publication-v1.json, SHA-256 8f123f99c2172de6557dc824856e97264f5200372daae1b11c87366401230225, verdict=pass. The implementation-gate QA and MPED reviews returned GO; just e2e passed 5/5 and just e2e-full passed 26/26.
<!-- SECTION:FINAL_SUMMARY:END -->
