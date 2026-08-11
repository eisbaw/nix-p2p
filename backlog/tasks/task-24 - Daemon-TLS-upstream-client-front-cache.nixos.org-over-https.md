---
id: TASK-24
title: Daemon TLS upstream client (front cache.nixos.org over https)
status: To Do
assignee: []
created_date: '2026-08-08 08:16'
updated_date: '2026-08-11 06:00'
labels:
  - wave1-followup
  - daemon
dependencies:
  - TASK-22
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-4 shipped the daemon upstream client (UpstreamHttp) as plain HTTP only (daemon/src/upstream.rs parse_authority rejects https). Fronting the real cache.nixos.org needs TLS. Wave-1 tests all use the loopback mock/testproxy over HTTP, so this is out of wave-1 scope but required before the daemon is useful against the real CDN. Sibling of task-22 (testproxy TLS). Add a TLS-capable connector (rustls) behind the same UpstreamHttp::send path; keep auto-decompression OFF.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 https:// upstream base is accepted and connects over TLS
- [ ] #2 verbatim byte forwarding + no auto-decompression preserved over TLS (AC#6 property holds)
- [ ] #3 TLS validates the certificate chain against configured/system roots and validates hostname/SNI; production mode has no insecure-skip-verify path.
- [ ] #4 End-to-end negative bites reject untrusted self-signed, wrong-hostname and expired certificates before forwarding/caching bytes, while a fixture-CA valid hostname and real cache.nixos.org succeed.
- [ ] #5 The daemon consumes tls-upstream-v1 unchanged: one 10000 ms total covers DNS, TCP connect and TLS handshake, with connect and handshake each capped at 5000 ms inside that total. Stalled stages fail within the bound and preserve fallback behavior; monotonic tests allow at most 1000 ms scheduler grace without extending configuration.
<!-- AC:END -->
