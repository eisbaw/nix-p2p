---
id: TASK-22
title: 'testproxy: TLS upstream support for fronting cache.nixos.org directly'
status: To Do
assignee: []
created_date: '2026-08-08 07:30'
updated_date: '2026-08-11 06:00'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies:
  - TASK-116
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After the global-first and LAN Iroh discovery vertical slices are complete, add TLS upstream support to testproxy so later production-shaped scenarios can front the real https://cache.nixos.org. The task-2 testproxy upstream client speaks plain HTTP only (see TODO in testproxy/src/http.rs upstream_get). Earlier tests deliberately use the local mock upstream, so this work is ordered after TASK-116 rather than displacing Iroh discovery. Preserve HTTP-stack independence: any TLS/HTTP client crate adopted must remain disjoint from the daemon stack through scripts/check-independence.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 testproxy can fetch from an https:// upstream base URL
- [ ] #2 chosen TLS/client crate added to HTTP_STACK_CRATES denylist and stays disjoint from the daemon's stack
- [ ] #3 The HTTPS client validates certificate chains against configured/system trust roots and validates DNS hostname/SNI; production configuration exposes no verification-disabled mode.
- [ ] #4 A fixture CA proves a valid hostname succeeds while untrusted self-signed, wrong-hostname and expired certificates are rejected before any response bytes are cached; neutralizing verification makes the test fail.
- [ ] #5 The frozen tls-upstream-v1 qualification budget is one 10000 ms total covering DNS, TCP connect and TLS handshake, with connect and handshake each capped at 5000 ms inside the same total. Deliberately stalled DNS/connect/handshake cases fail within the configured bound; monotonic tests allow at most 1000 ms scheduler grace and cannot extend the deadline in-run.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Ordering revision 2026-08-11: TASK-22 depends on TASK-116 so the user-selected sequence is mechanical: global Iroh discovery and review, later LAN/direct-query Iroh, then HTTPS and compression, all before BitTorrent.
<!-- SECTION:NOTES:END -->
