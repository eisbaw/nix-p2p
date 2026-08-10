---
id: TASK-22
title: 'testproxy: TLS upstream support for fronting cache.nixos.org directly'
status: To Do
assignee: []
created_date: '2026-08-08 07:30'
updated_date: '2026-08-10 22:55'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The task-2 testproxy upstream client speaks plain HTTP only (see TODO in testproxy/src/http.rs upstream_get). Wave-1 tests all use the local mock upstream, so fronting the real https://cache.nixos.org was deliberately deferred rather than pulling a TLS stack into the dependency-free fixture. If a scenario ever needs the proxy in front of the real cache over TLS, add HTTPS support - and note the HTTP-stack independence denylist in scripts/check-independence.py: any TLS/HTTP client crate adopted must not be one the daemon also uses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 testproxy can fetch from an https:// upstream base URL
- [ ] #2 chosen TLS/client crate added to HTTP_STACK_CRATES denylist and stays disjoint from the daemon's stack
- [ ] #3 The HTTPS client validates certificate chains against configured/system trust roots and validates DNS hostname/SNI; production configuration exposes no verification-disabled mode.
- [ ] #4 A fixture CA proves a valid hostname succeeds while untrusted self-signed, wrong-hostname and expired certificates are rejected before any response bytes are cached; neutralizing verification makes the test fail.
- [ ] #5 DNS/connect/TLS-handshake work is covered by a numeric total deadline and a deliberately stalled handshake fails within the asserted bound.
<!-- AC:END -->
