---
id: TASK-138
title: Iroh DNS/pkarr NodeId-to-address lookup capability
status: Done
assignee:
  - '@me'
created_date: '2026-08-11 06:00'
updated_date: '2026-08-11 19:42'
labels:
  - iroh
  - discovery
  - node
  - lookup
  - dns
  - pkarr
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement only the explicit default-off public NodeId-to-dialable-address lookup capability consumed by Iroh discovery. Given an asker-supplied NodeId, query a configured DNS/pkarr namespace and return validated direct/relay location candidates with provenance. Do not publish this node, enable relay transport, look up content, enumerate peers, use LAN discovery or run the combined connection journey. Emit a versioned pass|no_go artifact for TASK-89.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Lookup is a separate typed default-off capability. Query-only publishes nothing and enabling it performs no content lookup, relay connection or LAN discovery; disabled/offline-test emits zero DNS/pkarr lookup packets. Source and packet mutations prove the boundary.
- [x] #2 The API accepts only an asker-supplied NodeId and returns bounded candidate locations plus source/version/expiry/sequence metadata. It has no peer-list or inventory enumeration operation and rejects wildcard/unspecified/malformed/untrusted records.
- [x] #3 One NodeId resolution has a 10000 ms total deadline including DNS/pkarr work. Empty namespace, outage, bad signature, stale/replayed/expired record and no dialable candidate return typed distinct UNAVAILABLE reasons within the deadline, never content MISS; monotonic tests allow at most 1000 ms scheduler grace.
- [x] #4 Golden and mutation tests cover signature/version/namespace, sequence rollback, duplicate candidates, IPv4/IPv6 scope, malformed addresses, expiry and stale cache invalidation. Removing any validation makes a test fail.
- [x] #5 External n0/public DNS/pkarr queries, accounts, credentials, cost or infrastructure require a named owner and explicit authorization. Otherwise only a locally operated routed service is queried and evidence is labelled production-shaped.
- [x] #6 Emit iroh-node-lookup-v1 verdict=pass|no_go with final tree/evidence/schema hashes and failed constraints. Ordinary fixable implementation/test defects remain failure; TASK-89 validates the artifact and propagates an evidenced no_go.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation started 2026-08-11 under phase3 after TASK-137 implementation/evidence commits 56e5bca and d331734. Scope is strict default-off query-only NodeId lookup through the pinned signed pkarr authority: typed failures, bounded candidates, monotonic runtime cache/high-water, no publish/content/relay/LAN side effects, and production-shaped routed evidence. TASK-89 connection composition remains out of scope.

Completed with implementation commit 001d452 and evidence-boundary correction b46bbba. Canonical routed run r1b9786-9b4cd124428b uses the explicit all-TCP/UDP product-transport scope; autonomous kernel ICMP/IGMP/MLD convergence is honestly excluded. Carry forward Iroh learned-path expiry invalidation and per-profile address-class policy to TASK-89/TASK-120.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented explicit default-off signed NodeId-to-address lookup with a single asker-supplied NodeId, 16-candidate bound, one absolute 10000 ms deadline, typed outage/signature/replay/expiry/withdrawal/no-candidate failures, query-only runtime integration, and no publish/content/relay/LAN side effects. Canonical iroh-node-lookup-v1 artifact verdict=pass at artifacts/iroh-node-lookup-v1.json, SHA-256 566f1d21e4995896b7fe8ea473488134154efc13b8818f0a6ff1b9c6158957a4, bound to b46bbba2fe9e4f67a49afa299f6bf35ea4063afb. Evidence contains 13 routed observations, 89 manifest entries, ten lookup arms, and zero TCP/UDP packets in all three disabled controls. Verification passed 442 Rust tests, 15 focused lookup tests, 5/5 normal E2E, 26/26 full E2E, all 11 flake checks, schema validation, mutation tests, and independent QA/architecture gates.
<!-- SECTION:FINAL_SUMMARY:END -->
