---
id: TASK-22
title: 'testproxy: TLS upstream support for fronting cache.nixos.org directly'
status: To Do
assignee: []
created_date: '2026-08-08 07:30'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The task-2 testproxy upstream client speaks plain HTTP only (see TODO in testproxy/src/http.rs upstream_get). Wave-1 tests all use the local mock upstream, so fronting the real https://cache.nixos.org was deliberately deferred rather than pulling a TLS stack into the dependency-free fixture. If a scenario ever needs the proxy in front of the real cache over TLS, add HTTPS support - and note the HTTP-stack independence denylist in scripts/check-independence.py: any TLS/HTTP client crate adopted must not be one the daemon also uses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 testproxy can fetch from an https:// upstream base URL
- [ ] #2 chosen TLS/client crate added to HTTP_STACK_CRATES denylist and stays disjoint from the daemon's stack
<!-- AC:END -->
